/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "TargetDescription.h"

#include <sstream>

#include "GdbServerConnection.h"
#include "kernel_abi.h"

namespace rr {

class FeatureStream {
public:
  string result() { return stream.str(); }

  template <typename Any>
  friend FeatureStream& operator<<(FeatureStream& stream, Any any);

private:
  stringstream stream;
  const char* arch_prefix;
};

template <typename Any>
FeatureStream& operator<<(FeatureStream& stream, Any any) {
  stream.stream << any;
  return stream;
}

template <>
FeatureStream& operator<<(FeatureStream& stream, rr::SupportedArch arch) {
  stream << "<architecture>";
  switch (arch) {
    case rr::x86:
      stream << "i386";
      stream.arch_prefix = "32bit-";
      break;
    case rr::x86_64:
      stream << "i386:x86-64";
      stream.arch_prefix = "64bit-";
      break;
    case rr::aarch64:
      stream << "aarch64";
      stream.arch_prefix = "aarch64-";
      break;
  }
  stream << "</architecture>\n";
  return stream;
}

template <>
FeatureStream& operator<<(FeatureStream& stream, TargetFeature feature) {
  DEBUG_ASSERT(stream.arch_prefix != nullptr &&
               "No architecture has been provided to description");
  stream << R"(  <xi:include href=")" << stream.arch_prefix;
  switch (feature) {
    case TargetFeature::Core:
      stream << "core.xml";
      break;
    case TargetFeature::Linux:
      stream << "linux.xml";
      break;
    case TargetFeature::SSE:
      stream << "sse.xml";
      break;
    case TargetFeature::AVX:
      stream << "avx.xml";
      break;
    case TargetFeature::AVX512:
      stream << "avx512.xml";
      break;
    case TargetFeature::PKeys:
      stream << "pkeys.xml";
      break;
    case TargetFeature::Segment:
      stream << "seg.xml";
      break;
    case TargetFeature::FPU:
      stream << "fpu.xml";
      break;
    case TargetFeature::PAuth:
      stream << "pauth.xml";
      break;
  }
  stream << R"("/>)" << '\n';
  return stream;
}

TargetDescription::TargetDescription(rr::SupportedArch arch,
                                     uint32_t cpu_features)
    : arch(arch), target_features() {

  // default-assumed registers per arch
  switch (arch) {
    case rr::x86:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::SSE);
      target_features.push_back(TargetFeature::Linux);
      break;
    case rr::x86_64:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::SSE);
      target_features.push_back(TargetFeature::Linux);
      target_features.push_back(TargetFeature::Segment);
      break;
    case rr::aarch64:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::FPU);
      break;
  }

  if (cpu_features & rr::GdbServerConnection::CPU_AVX) {
    DEBUG_ASSERT((arch == rr::x86 || arch == rr::x86_64) && "unexpected arch");
    target_features.push_back(TargetFeature::AVX);
  }

  if (cpu_features & rr::GdbServerConnection::CPU_AVX512) {
    DEBUG_ASSERT((arch == rr::x86 || arch == rr::x86_64) && "unexpected arch");
    target_features.push_back(TargetFeature::AVX512);
  }

  if (cpu_features & rr::GdbServerConnection::CPU_PKU) {
    DEBUG_ASSERT((arch == rr::x86 || arch == rr::x86_64) && "unexpected arch");
    target_features.push_back(TargetFeature::PKeys);
  }

  if (cpu_features & rr::GdbServerConnection::CPU_AARCH64_PAUTH) {
    DEBUG_ASSERT((arch == rr::aarch64) && "unexpected arch");
    target_features.push_back(TargetFeature::PAuth);
  }
}

static const char header[] = R"(<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
)";

string TargetDescription::to_xml() const {
  FeatureStream fs;
  fs << header << arch << "<osabi>GNU/Linux</osabi>\n";
  for (const auto feature : target_features) {
    fs << feature;
  }
  fs << "</target>";

  return fs.result();
}
} // namespace rr