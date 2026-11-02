#pragma once

#include <keywright/secrets.h>

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace kwr {

	/// <summary>
	/// The per-user keywright configuration directory (UTF-8), from the OS's own folder APIs.
	/// It is not created, and config.toml lives inside it.
	/// </summary>
	/// <exception cref="std::runtime_error">The OS could not report the folder.</exception>
	std::string cfgdir();

	/// <summary>Reads a whole file. All paths in this header are UTF-8.</summary>
	/// <exception cref="std::runtime_error">The file is missing or unreadable.</exception>
	std::vector<std::byte> readfile(const std::string& path);

	/// <summary>Reads a keyfile into locked, wiped memory. Files over 1 MiB are rejected.</summary>
	/// <exception cref="std::runtime_error">Missing, unreadable, or too large.</exception>
	secret_buffer readkey(const std::string& path);

	/// <summary>
	/// Replaces the file atomically: writes a temp file in the same directory, flushes it to disk,
	/// then renames it over the target. A failure leaves the original intact.
	/// </summary>
	/// <exception cref="std::runtime_error">Any I/O failure.</exception>
	void writefile(const std::string& path, std::span<const std::byte> data);

	/// <summary>Creates a new owner-only file and fails if it already exists.</summary>
	/// <exception cref="std::runtime_error">The file exists, or any I/O failure.</exception>
	void newfile(const std::string& path, std::span<const std::byte> data);

	bool isfile(const std::string& path);
	bool isdir(const std::string& path);
	std::string joinpath(const std::string& dir, const std::string& name);

	/// <summary>Prompts on the terminal without echo and reads one line (up to 1023 bytes).</summary>
	/// <exception cref="std::runtime_error">No terminal is available.</exception>
	secret_buffer askpass(const std::string& prompt);

	/// <summary>
	/// Puts text on the clipboard, flagged to stay out of clipboard history and cloud sync where the
	/// OS supports it, then blocks for the given seconds (or until Ctrl-C) and clears it only if
	/// nothing else has been copied in the meantime.
	/// </summary>
	/// <exception cref="std::runtime_error">The clipboard is unavailable or unsupported on this OS.</exception>
	void cliphold(std::span<const std::byte> text, unsigned seconds);

	/// <summary>Creates a folder and any missing parents. Succeeds if it already exists.</summary>
	/// <exception cref="std::runtime_error">Creation failed, or the path exists and is not a folder.</exception>
	void mkdirs(const std::string& path);

	/// <summary>
	/// Makes a path absolute against the current directory and tidies it lexically.
	/// The disk is not touched and links are not resolved.
	/// </summary>
	/// <exception cref="std::runtime_error">Empty path, or the current directory is unavailable.</exception>
	std::string abspath(const std::string& path);

	/// <summary>True if stdin is a terminal, meaning a person can be asked a question.</summary>
	bool ttyin();

	/// <summary>Prompts on the terminal and reads one line with echo (up to 1023 bytes), without the newline.</summary>
	/// <exception cref="std::runtime_error">No terminal is available, or the line is too long.</exception>
	std::string ask(const std::string& prompt);

	/// <summary>The folder part of a path, or an empty string if it has none.</summary>
	std::string parentdir(const std::string& path);

	/// <summary>True if the path is absolute on this OS.</summary>
	bool isabs(const std::string& path);
}
