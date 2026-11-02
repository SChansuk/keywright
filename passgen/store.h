#pragma once

#include <keywright/vault.h>

#include <cstddef>
#include <span>
#include <string>

namespace kwr {

	/// Resolves the vault file for a namespace.
	/// An existing directory, or a path ending in a separator, is a directory
	/// and gets the keyed filename. Anything else is used as the file path as given.
	std::string vpath(const std::string& save_to, std::span<const std::byte> keyfile, const std::string& ns);

	/// Maps "moderate" or "sensitive" to the vault KDF profile.
	vkdf kdfmap(const std::string& name);

}
