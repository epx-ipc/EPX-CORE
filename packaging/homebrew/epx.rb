# Homebrew formula template for the epx-ipc/homebrew-epx tap. The release
# workflow rewrites url/sha256/version on each tagged release; users then:
#   brew tap epx-ipc/epx && brew install epx
class Epx < Formula
  desc "Encrypted Process eXchange: local, authenticated, E2E-encrypted IPC"
  homepage "https://github.com/epx-ipc/EPX-CORE"
  url "https://github.com/epx-ipc/EPX-CORE/archive/refs/tags/v2.1.0.tar.gz"
  sha256 "REPLACED_BY_RELEASE_WORKFLOW"
  version "2.1.0"
  license "MIT"

  depends_on "cmake" => :build
  depends_on "libsodium"

  def install
    system "cmake", "-B", "build", "-S", ".",
           "-DCMAKE_BUILD_TYPE=Release",
           "-DEPX_BUILD_CAPI=ON", "-DEPX_BUILD_CLI=ON",
           "-DEPX_BUILD_EXAMPLES=OFF", "-DEPX_BUILD_TESTS=OFF",
           "-DEPX_INSTALL=ON",
           "-DCMAKE_INSTALL_PREFIX=#{prefix}"
    system "cmake", "--build", "build", "--parallel"
    system "cmake", "--install", "build"
  end

  test do
    assert_match "usage", shell_output("#{bin}/epx 2>&1", 2)
  end
end
