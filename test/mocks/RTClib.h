#pragma once

#include <cstdint>
#include <ctime>

class DateTime {
  std::tm value_{};
public:
  explicit DateTime(uint32_t seconds) {
    const std::time_t timestamp = seconds;
    value_ = *std::gmtime(&timestamp);
  }
  int hour() const { return value_.tm_hour; }
  int minute() const { return value_.tm_min; }
  int day() const { return value_.tm_mday; }
  int month() const { return value_.tm_mon + 1; }
  int year() const { return value_.tm_year + 1900; }
};
