#pragma once

#include <cstddef>
#include <string>

namespace kwr {

	inline constexpr std::size_t KEY_BYTES = 64;

	/// Creates a keyfile of KEY_BYTES random bytes at path.
	/// Fails if the file already exists. The file is owner-only.
	void keymake(const std::string& path);

}
