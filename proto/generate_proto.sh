# Generate SCION .proto files
protoc --c_out=. proto/control_plane/experimental/v1/seg_detached_extensions.proto
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c
mv proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c ../lib/proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.h
mv proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.h ../include/scion/proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.h

protoc --c_out=. proto/control_plane/v1/seg_extensions.proto
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/v1/seg_extensions.pb-c.c
mv proto/control_plane/v1/seg_extensions.pb-c.c ../lib/proto/control_plane/v1/seg_extensions.pb-c.c
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/v1/seg_extensions.pb-c.h
mv proto/control_plane/v1/seg_extensions.pb-c.h ../include/scion/proto/control_plane/v1/seg_extensions.pb-c.h

protoc --c_out=. proto/control_plane/v1/seg.proto
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/v1/seg.pb-c.c
mv proto/control_plane/v1/seg.pb-c.c ../lib/proto/control_plane/v1/seg.pb-c.c
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/control_plane/v1/seg.pb-c.h
mv proto/control_plane/v1/seg.pb-c.h ../include/scion/proto/control_plane/v1/seg.pb-c.h

protoc --c_out=. proto/crypto/v1/signed.proto
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/crypto/v1/signed.pb-c.c
mv proto/crypto/v1/signed.pb-c.c ../lib/proto/crypto/v1/signed.pb-c.c
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' proto/crypto/v1/signed.pb-c.h
mv proto/crypto/v1/signed.pb-c.h ../include/scion/proto/crypto/v1/signed.pb-c.h


# Generate Well-known types dependencies
protoc --c_out=. google/protobuf/timestamp.proto
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' google/protobuf/timestamp.pb-c.c
mv google/protobuf/timestamp.pb-c.c ../lib/google/protobuf/timestamp.pb-c.c
sed -i -e 's/#include "google\//#include "scion\/google\//g' -e 's/#include "proto\//#include "scion\/proto\//g' google/protobuf/timestamp.pb-c.h
mv google/protobuf/timestamp.pb-c.h ../include/scion/google/protobuf/timestamp.pb-c.h