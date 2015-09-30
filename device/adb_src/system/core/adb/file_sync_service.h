/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _FILE_SYNC_SERVICE_H_
#define _FILE_SYNC_SERVICE_H_

#ifdef HAVE_BIG_ENDIAN
static inline unsigned __swap_uint32(unsigned x) 
{
    return (((x) & 0xFF000000) >> 24)
        | (((x) & 0x00FF0000) >> 8)
        | (((x) & 0x0000FF00) << 8)
        | (((x) & 0x000000FF) << 24);
}
#define htoll(x) __swap_uint32(x)
#define ltohl(x) __swap_uint32(x)
#define MKID(a,b,c,d) ((d) | ((c) << 8) | ((b) << 16) | ((a) << 24))

static inline unsigned long long __swap_uint64(unsigned long long ll)
{ 
	return (((ll) >> 56)
		| (((ll) & 0x00ff000000000000) >> 40)
                | (((ll) & 0x0000ff0000000000) >> 24)
                | (((ll) & 0x000000ff00000000) >> 8)
                | (((ll) & 0x00000000ff000000) << 8)
                | (((ll) & 0x0000000000ff0000) << 24)
                | (((ll) & 0x000000000000ff00) << 40)
                | (((ll) << 56))) 
}
#define htol64(ll) __swap64(ll)
#define ltoh64(ll) __swap64(ll)

#else
#define htoll(x) (x)
#define ltohl(x) (x)
#define htol64(ll) (ll)
#define ltoh64(ll) (ll)
#define MKID(a,b,c,d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))
#endif

#define ID_STAT MKID('S','T','A','T')
#define ID_LIST MKID('L','I','S','T')
#define ID_ULNK MKID('U','L','N','K')
#define ID_SEND MKID('S','E','N','D')
#define ID_RECV MKID('R','E','C','V')
#define ID_DENT MKID('D','E','N','T')
#define ID_DONE MKID('D','O','N','E')
#define ID_DATA MKID('D','A','T','A')
#define ID_OKAY MKID('O','K','A','Y')
#define ID_FAIL MKID('F','A','I','L')
#define ID_QUIT MKID('Q','U','I','T')

//Add for SafeDisk
#define ID_AUTH MKID('A', 'U', 'T', 'H')
#define ID_PSWD MKID('P', 'S', 'W', 'D')
#define ID_LEFT MKID('L', 'E', 'F', 'T')
#define ID_RMOV MKID('R', 'M', 'O', 'V')
#define ID_MOVE MKID('M', 'O', 'V', 'E')
#define ID_COPY MKID('C', 'O', 'P', 'Y')
#define ID_UMNT MKID('U', 'M', 'N', 'T')
#define ID_REST MKID('R', 'E', 'S', 'T')

//Send raw file, and Recv raw file without de/encypt
#define ID_SERA MKID('S','E','R','A')
#define ID_RERA MKID('R','E','R','A')

typedef union {
    unsigned id;
    struct {
        unsigned id;
        unsigned namelen;
    } req;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
    } stat;
    struct {
        unsigned id;
        unsigned mode;
        unsigned size;
        unsigned time;
        unsigned namelen;
    } dent;
    struct {
        unsigned id;
        unsigned size;
    } data;
    struct {
        unsigned id;
        unsigned msglen;
    } status;    
} syncmsg;

typedef void (*sync_ls_cb)(unsigned mode, unsigned size, unsigned time, const char *name, void *cookie);

void file_sync_service(int fd, void *cookie);
int do_sync_ls(const char *path);
int do_sync_push(const char *lpath, const char *rpath, int verifyApk);
int do_sync_sync(const char *lpath, const char *rpath, int listonly);
int do_sync_pull(const char *rpath, const char *lpath);

// added by hongtaoxu
int eagle_do_sync_remove(const char *path);
int eagle_do_sync_ls(const char *path, sync_ls_cb func, void *cookie);
int do_sync_auth(const char *password);
int do_sync_passwd(const char *old_passwd, const char *new_passwd);
int do_sync_get_left();
int do_sync_mv(const char *oldpath, const char *newpath);
int do_sync_umount();
int do_sync_copy(const char *oldpath, const char *newpath);
int do_sync_reset();

#define SYNC_DATA_MAX (64*1024)

#endif
