// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdexcept>

#include <flatfile.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/system.h>
#include <fstream>

FlatFileSeq::FlatFileSeq(fs::path dir, const char* prefix, size_t chunk_size) :
    m_dir(std::move(dir)),
    m_prefix(prefix),
    m_chunk_size(chunk_size)
{
    if (chunk_size == 0) {
        throw std::invalid_argument("chunk_size must be positive");
    }
}

std::string FlatFilePos::ToString() const
{
    return strprintf("FlatFilePos(nFile=%i, nPos=%i)", nFile, nPos);
}

fs::path FlatFileSeq::FileName(const FlatFilePos& pos) const
{
    return m_dir / strprintf("%s%05u.dat", m_prefix, pos.nFile);
}

fs::path FlatFileSeq::FileName(unsigned int pos) const
{
    return m_dir / strprintf("%s%05u.dat", m_prefix, pos);
}

FILE* FlatFileSeq::Open(const FlatFilePos& pos, bool read_only)
{
    if (pos.IsNull()) {
        return nullptr;
    }
    fs::path path = FileName(pos);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, read_only ? "rb": "rb+");
    if (!file && !read_only)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos && fseek(file, pos.nPos, SEEK_SET)) {
        LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
        fclose(file);
        return nullptr;
    }
    return file;
}

FILE* FlatFileSeq::Open(unsigned int nPos,bool read_only) {
    fs::path path = m_dir / "tmp.dat";
    FILE* file = fsbridge::fopen(path, read_only ? "rb" : "rb+");
    if (!file && !read_only)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if(fseek(file, nPos, SEEK_SET)) {
        LogPrintf("Unable to seek to position %u of %s\n", nPos, path.string());
        fclose(file);
        return nullptr;
    }
    return file;
}

bool FlatFileSeq::Remove(unsigned int pos) {
    fs::path path = FileName(pos);
    bool failed = !fs::ifstream(path);
    if(failed) {
        LogPrintf("Fail to remove file %s: file is not exist\n",path.c_str());
        return false;
    } 
    int ret = fs::remove(path);
    if(ret){
        LogPrintf("Fail to remove file %s: file could not remove\n",path.c_str());
        return false;
    }
    return true;
    
}

bool FlatFileSeq::RenameTmp(unsigned int pos) {
    fs::path tmp_path = m_dir / "tmp.dat";
    fs::path pos_path = FileName(pos);
    bool ret_tmp = !fs::ifstream(tmp_path);
    bool ret_pos = !fs::ifstream(pos_path);
    if(ret_tmp) {
        LogPrintf("Fail to open tmp.dat\n");
        return false;
    } 
    if(!ret_pos){
        LogPrintf("%s is exist, removing...\n",pos_path.c_str());
        bool ret = Remove(pos);
        if(!ret) return false;
    }
    fs::rename(tmp_path, pos_path);
    return true;
}

size_t FlatFileSeq::Allocate(const FlatFilePos& pos, size_t add_size, bool& out_of_space)
{
    out_of_space = false;

    unsigned int n_old_chunks = (pos.nPos + m_chunk_size - 1) / m_chunk_size;
    unsigned int n_new_chunks = (pos.nPos + add_size + m_chunk_size - 1) / m_chunk_size;
    if (n_new_chunks > n_old_chunks) {
        size_t old_size = pos.nPos;
        size_t new_size = n_new_chunks * m_chunk_size;
        size_t inc_size = new_size - old_size;

        if (CheckDiskSpace(m_dir, inc_size)) {
            FILE *file = Open(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in %s%05u.dat\n", new_size, m_prefix, pos.nFile);
                AllocateFileRange(file, pos.nPos, inc_size);
                fclose(file);
                return inc_size;
            }
        } else {
            out_of_space = true;
        }
    }
    return 0;
}

size_t FlatFileSeq::Allocate(const size_t tempFileSize, bool& out_of_space){
    if (CheckDiskSpace(m_dir, tempFileSize)) {
            FILE *file = fsbridge::fopen(m_dir / "tmp.dat", "rb+") ;
            if (file) {
                LogPrintf("Pre-allocating temperate file to order temp.dat\n");
                AllocateFileRange(file, 0, tempFileSize);
                fclose(file);
                return tempFileSize;
            }
        } else {
            out_of_space = true;
        }
    
    return 0;
}

bool FlatFileSeq::Flush(const FlatFilePos& pos, bool finalize)
{
    FILE* file = Open(FlatFilePos(pos.nFile, 0)); // Avoid fseek to nPos
    if (!file) {
        return error("%s: failed to open file %d", __func__, pos.nFile);
    }
    if (finalize && !TruncateFile(file, pos.nPos)) {
        fclose(file);
        return error("%s: failed to truncate file %d", __func__, pos.nFile);
    }
    if (!FileCommit(file)) {
        fclose(file);
        return error("%s: failed to commit file %d", __func__, pos.nFile);
    }

    fclose(file);
    return true;
}
