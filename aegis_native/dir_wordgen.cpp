// C++ helper for generating directory bruteforce candidate URLs.
//
// Exposed to Python via pybind11 as `aegis_native.dir_wordgen`.
//
// Python usage:
//
//     from aegis_native import dir_wordgen
//     urls = dir_wordgen.generate_paths(
//         "https://example.com/",
//         ["admin", "login"],
//         ["php", "html"],
//         10,
//     )
//     # urls: ["https://example.com/admin/", "https://example.com/admin",
//     #        "https://example.com/admin.php", "https://example.com/admin.html", ...]

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <string>
#include <vector>

namespace py = pybind11;

namespace {

std::vector<std::string> generate_paths_internal(
    const std::string &base_url,
    const std::vector<std::string> &words,
    const std::vector<std::string> &exts,
    std::size_t max_exts
) {
    std::vector<std::string> urls;

    // Pre‑reserve a rough upper bound to reduce reallocations
    std::size_t per_word = 2 + std::min<std::size_t>(exts.size(), max_exts);
    urls.reserve(words.size() * per_word);

    for (const auto &word : words) {
        // Directory variant
        urls.emplace_back(base_url + word + "/");
        // File without extension
        urls.emplace_back(base_url + word);

        // Limited extensions
        std::size_t count = 0;
        for (const auto &ext : exts) {
            if (count >= max_exts) {
                break;
            }
            urls.emplace_back(base_url + word + "." + ext);
            ++count;
        }
    }

    return urls;
}

}  // namespace

PYBIND11_MODULE(dir_wordgen, m) {
    m.doc() = "C++ helper for generating directory bruteforce candidate URLs";

    m.def(
        "generate_paths",
        &generate_paths_internal,
        py::arg("base_url"),
        py::arg("words"),
        py::arg("exts"),
        py::arg("max_exts") = 10,
        R"pbdoc(
Generate candidate URLs for directory bruteforce.

Args:
    base_url (str): Base URL ending with '/'.
    words (List[str]): Wordlist entries (e.g. ['admin', 'login']).
    exts (List[str]): File extensions (e.g. ['php', 'html']).
    max_exts (int): Maximum number of extensions per word.

Returns:
    List[str]: Full URLs to test.
)pbdoc"
    );
}


