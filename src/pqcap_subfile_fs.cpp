#include "pqcap_subfile_fs.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_opener.hpp"

#include <stdexcept>

namespace duckdb {

static constexpr size_t PREFIX_LEN = sizeof("pqcap-subfile://") - 1;

bool PqcapSubFileSystem::CanHandleFile(const string &fpath) {
	return fpath.size() > PREFIX_LEN && fpath.compare(0, PREFIX_LEN, "pqcap-subfile://") == 0;
}

static uint64_t ParseDecimalUint64(const string &s, const string &field, const string &path) {
	if (s.empty()) {
		throw IOException("malformed pqcap-subfile path (empty " + field + "): " + path);
	}
	for (auto c : s) {
		if (c < '0' || c > '9') {
			throw IOException("malformed pqcap-subfile path (non-digit in " + field + "): " + path);
		}
	}
	try {
		size_t consumed = 0;
		auto v = std::stoull(s, &consumed, 10);
		if (consumed != s.size()) {
			throw IOException("malformed pqcap-subfile path (trailing chars in " + field + "): " + path);
		}
		return v;
	} catch (std::out_of_range &) {
		throw IOException("malformed pqcap-subfile path (" + field + " exceeds uint64): " + path);
	} catch (std::invalid_argument &) {
		throw IOException("malformed pqcap-subfile path (could not parse " + field + "): " + path);
	}
}

unique_ptr<FileHandle> PqcapSubFileSystem::OpenFile(const string &path, FileOpenFlags flags,
                                                    optional_ptr<FileOpener> opener) {
	if (!flags.OpenForReading() || flags.OpenForWriting()) {
		throw IOException("pqcap-subfile filesystem is read-only");
	}
	if (!opener) {
		throw IOException("pqcap-subfile filesystem requires a FileOpener for context: " + path);
	}
	if (!CanHandleFile(path)) {
		throw IOException("not a pqcap-subfile path: " + path);
	}
	auto stripped = path.substr(PREFIX_LEN);
	auto bang = stripped.find('!');
	if (bang == string::npos) {
		throw IOException("malformed pqcap-subfile path (missing '!' separator): " + path);
	}
	auto header = stripped.substr(0, bang);
	auto underlying = stripped.substr(bang + 1);
	auto underscore = header.find('_');
	if (underscore == string::npos) {
		throw IOException("malformed pqcap-subfile path (missing '_' separator): " + path);
	}
	auto offset = ParseDecimalUint64(header.substr(0, underscore), "offset", path);
	auto size = ParseDecimalUint64(header.substr(underscore + 1), "size", path);

	auto context = opener->TryGetClientContext();
	if (!context) {
		throw IOException("pqcap-subfile filesystem requires a ClientContext: " + path);
	}
	auto &fs = FileSystem::GetFileSystem(*context);
	auto inner = fs.OpenFile(underlying, flags);
	if (!inner) {
		throw IOException("could not open underlying file: " + underlying);
	}
	if (!(*inner).CanSeek()) {
		throw IOException("underlying file is not seekable, pqcap requires range reads: " + underlying);
	}
	return make_uniq<PqcapSubFileHandle>(*this, path, flags, std::move(inner), static_cast<idx_t>(offset),
	                                     static_cast<idx_t>(size));
}

void PqcapSubFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) {
	auto &h = static_cast<PqcapSubFileHandle &>(handle);
	if (location >= h.sub_size) {
		return;
	}
	auto to_read = MinValue(static_cast<idx_t>(nr_bytes), h.sub_size - location);
	if (to_read == 0) {
		return;
	}
	(*h.inner_handle).Read(buffer, static_cast<int64_t>(to_read), location + h.base_offset);
}

int64_t PqcapSubFileSystem::Read(FileHandle &handle, void *buffer, int64_t nr_bytes) {
	auto &h = static_cast<PqcapSubFileHandle &>(handle);
	if (h.seek_pos >= h.sub_size) {
		return 0;
	}
	auto to_read = MinValue(static_cast<idx_t>(nr_bytes), h.sub_size - h.seek_pos);
	if (to_read == 0) {
		return 0;
	}
	(*h.inner_handle).Read(buffer, static_cast<int64_t>(to_read), h.seek_pos + h.base_offset);
	h.seek_pos += to_read;
	return static_cast<int64_t>(to_read);
}

int64_t PqcapSubFileSystem::GetFileSize(FileHandle &handle) {
	return static_cast<int64_t>(static_cast<PqcapSubFileHandle &>(handle).sub_size);
}

void PqcapSubFileSystem::Seek(FileHandle &handle, idx_t location) {
	static_cast<PqcapSubFileHandle &>(handle).seek_pos = location;
}

void PqcapSubFileSystem::Reset(FileHandle &handle) {
	static_cast<PqcapSubFileHandle &>(handle).seek_pos = 0;
}

idx_t PqcapSubFileSystem::SeekPosition(FileHandle &handle) {
	return static_cast<PqcapSubFileHandle &>(handle).seek_pos;
}

bool PqcapSubFileSystem::OnDiskFile(FileHandle &handle) {
	auto &h = static_cast<PqcapSubFileHandle &>(handle);
	return (*h.inner_handle).OnDiskFile();
}

FileType PqcapSubFileSystem::GetFileType(FileHandle &handle) {
	auto &inner = *static_cast<PqcapSubFileHandle &>(handle).inner_handle;
	return inner.file_system.GetFileType(inner);
}

timestamp_t PqcapSubFileSystem::GetLastModifiedTime(FileHandle &handle) {
	auto &inner = *static_cast<PqcapSubFileHandle &>(handle).inner_handle;
	return inner.file_system.GetLastModifiedTime(inner);
}

} // namespace duckdb
