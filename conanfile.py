from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.cmake import cmake_layout, CMake, CMakeDeps, CMakeToolchain
from conan.tools.files import get, copy
from conan.tools.scm import Git


class OpensslEvpWasm(ConanFile):
    name = "openssl-evp-wasm"
    license = "MIT"
    author = "Peter Bennion pcbennion@gmail.com, Qrypt Inc info@qrypt.com"
    url = "https://github.com/pcbennion/openssl-evp-wasm"
    description = ("Webassembly bindings for the OpenSSL EVP crypto interface.")
    topics = ("openssl", "webassembly", "cryptography", "interface")
    settings = "os", "compiler", "build_type", "arch"
    options = {"modularize": [True, False]}
    default_options = {"modularize": False}

    def set_version(self):
        # If no version has been set, set it to the current git branch name
        git = Git(self, self.recipe_folder)
        branch = git.run("rev-parse --abbrev-ref HEAD")
        self.version = self.version or branch

    def configure(self):
        pass

    def requirements(self):
        self.requires("openssl/3.5.2")

    def build_requirements(self):
        self.build_requires("emsdk/3.1.50")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()

    def source(self):
        conandata_sources = self.conan_data.get("sources", {}).get(self.version, {})
        if not conandata_sources:
            raise ConanInvalidConfiguration("In-cache builds are only supported for released versions.")
        get(self, **conandata_sources, strip_root=True)

    def build(self):
        cmake = CMake(self)
        cmake.configure(
            build_script_folder=self.source_folder,
            variables={"MODULARIZE": self.options.modularize}
        )
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def deploy(self):
        copy(self, "*", self.package_folder, self.deploy_folder, excludes="test")
