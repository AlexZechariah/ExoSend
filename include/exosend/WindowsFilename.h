#pragma once

#include <string>

namespace ExoSend {

// Returns true if the filename is already a safe Windows filename and requires no changes.
// Does not accept path separators, ADS stream specifiers, reserved device names, or trailing
// spaces/dots. Intended for defense-in-depth on receiver-side filenames provided by peers.
bool isSafeWindowsFilename(const std::string& name);

// Sanitizes a peer-provided filename into a safe Windows filename in place.
// Returns false if the filename cannot be made safe (for example empty, ADS specifier).
bool sanitizeWindowsFilenameInPlace(std::string& name);

}  // namespace ExoSend

