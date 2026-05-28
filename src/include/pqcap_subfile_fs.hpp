#pragma once

#include "duckdb/common/file_system.hpp"

namespace duckdb {

class PqcapSubFileHandle final : public FileHandle {
	friend class PqcapSubFileSystem;

public:
	PqcapSubFileHandle(FileSystem &file_system, const string &path, FileOpenFlags flags,
	                   unique_ptr<FileHandle> inner_handle_p, idx_t base_offset_p, idx_t sub_size_p)
	    : FileHandle(file_system, path, flags), inner_handle(std::move(inner_handle_p)), base_offset(base_offset_p),
	      sub_size(sub_size_p), seek_pos(0) {
	}

	void Close() override {
		if (inner_handle) {
			(*inner_handle).Close();
		}
	}

private:
	unique_ptr<FileHandle> inner_handle;
	idx_t base_offset;
	idx_t sub_size;
	idx_t seek_pos;
};

class PqcapSubFileSystem final : public FileSystem {
public:
	PqcapSubFileSystem() : FileSystem() {
	}

	std::string GetName() const override {
		return "PqcapSubFileSystem";
	}
	bool CanHandleFile(const string &fpath) override;
	bool CanSeek() override {
		return true;
	}

	unique_ptr<FileHandle> OpenFile(const string &path, FileOpenFlags flags, optional_ptr<FileOpener> opener) override;

	void Read(FileHandle &handle, void *buffer, int64_t nr_bytes, idx_t location) override;
	int64_t Read(FileHandle &handle, void *buffer, int64_t nr_bytes) override;
	int64_t GetFileSize(FileHandle &handle) override;
	void Seek(FileHandle &handle, idx_t location) override;
	void Reset(FileHandle &handle) override;
	idx_t SeekPosition(FileHandle &handle) override;

	bool OnDiskFile(FileHandle &handle) override;
	FileType GetFileType(FileHandle &handle) override;
	timestamp_t GetLastModifiedTime(FileHandle &handle) override;

	vector<OpenFileInfo> Glob(const string &path, FileOpener *opener) override {
		if (path.size() >= 16 && path.substr(0, 16) == "pqcap-subfile://") {
			return {OpenFileInfo(path)};
		}
		return {};
	}
	bool FileExists(const string &filename, optional_ptr<FileOpener> opener) override {
		return filename.size() >= 16 && filename.substr(0, 16) == "pqcap-subfile://";
	}
};

} // namespace duckdb
