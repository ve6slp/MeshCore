// Native tests for the single shared write-gate mechanism now used
// DIRECTLY by all 8 of DataStore's destructive-write methods (see
// DataStore.cpp's savePrefs/saveContacts/saveChannels/putBlobByKey x2/
// deleteBlobByKey x2/saveMainIdentity) -- not a parallel/duplicated
// test-only model. Exercises the EXACT production template with a
// byte-backed fake `perform_fn` so both "never invoked, zero mutation"
// and "invoked exactly once, real result forwarded" are directly
// observable, not merely inferred from a manual call-count substitute.
#include <gtest/gtest.h>
#include <helpers/ota/OtaWriteGate.h>
#include <vector>

namespace {

// Simulates the underlying byte-backed "disk" a real perform_fn would
// mutate (e.g. a File::write()) -- if guardedPersist() ever invoked
// perform_fn while disallowed, this buffer would change; the tests below
// assert it never does.
struct FakeDisk {
  std::vector<uint8_t> bytes;
  int call_count = 0;

  bool performWrite(const std::vector<uint8_t>& new_bytes) {
    ++call_count;
    bytes = new_bytes;
    return true;
  }
};

}  // namespace

TEST(OtaWriteGateTest, DisallowedNeverInvokesPerformFnAndReturnsFalse) {
  FakeDisk disk;
  disk.bytes = {1, 2, 3};  // pre-existing persisted content.
  const bool ok = ota_write_gate::guardedPersist(/*disallowed=*/true, [&]() {
    return disk.performWrite({9, 9, 9});
  });
  EXPECT_FALSE(ok);
  EXPECT_EQ(0, disk.call_count);
  EXPECT_EQ((std::vector<uint8_t>{1, 2, 3}), disk.bytes);  // byte-identical, untouched.
}

TEST(OtaWriteGateTest, AllowedInvokesPerformFnExactlyOnceAndForwardsRealResult) {
  FakeDisk disk;
  disk.bytes = {1, 2, 3};
  const bool ok = ota_write_gate::guardedPersist(/*disallowed=*/false, [&]() {
    return disk.performWrite({9, 9, 9});
  });
  EXPECT_TRUE(ok);
  EXPECT_EQ(1, disk.call_count);
  EXPECT_EQ((std::vector<uint8_t>{9, 9, 9}), disk.bytes);
}

TEST(OtaWriteGateTest, AllowedForwardsAGenuinePerformFnFailureHonestly) {
  // A genuine I/O fault inside perform_fn (e.g. a real partial write)
  // must still be reported as `false` when writes ARE allowed -- the
  // gate itself must never mask a real failure as success.
  int calls = 0;
  const bool ok = ota_write_gate::guardedPersist(/*disallowed=*/false, [&]() {
    ++calls;
    return false;  // simulated genuine write failure.
  });
  EXPECT_FALSE(ok);
  EXPECT_EQ(1, calls);
}

TEST(OtaWriteGateTest, DisallowedNeverConfusedWithAGenuinePerformFnFailure) {
  // Both the disallowed-policy-refusal case and a genuine perform_fn
  // failure return `false` from guardedPersist() itself (callers must
  // consult DataStore::destructiveWritesDisallowed() separately to tell
  // them apart -- see MyMesh.h/.cpp's fault-latch call sites), but this
  // asserts the POLICY case specifically never reaches perform_fn at
  // all, regardless of what perform_fn itself would have returned.
  int calls = 0;
  const bool ok = ota_write_gate::guardedPersist(/*disallowed=*/true, [&]() {
    ++calls;
    return true;  // would have reported success, must never run.
  });
  EXPECT_FALSE(ok);
  EXPECT_EQ(0, calls);
}
