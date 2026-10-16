Unmodified selected C decoder/filter files from 7-Zip / LZMA SDK 26.04.
LzmaDec.c, LzmaDec.h, Bra.c, Bra.h and supporting headers identify themselves
as public domain, Copyright/author Igor Pavlov. The upstream package's complete
License.txt is retained; unrelated 7-Zip LGPL/unRAR components are not used.

sources.json pins exact upstream URLs and SHA256 for every imported file.
Production uses the persistent dictionary API with fixed, instance-owned
7040-byte probability storage; no SDK Allocate/Free or one-shot API is called.
The caller's bounded raw output is the dictionary. ARMT inverse filtering is
explicitly authenticated and enabled only by nRF board backends.
