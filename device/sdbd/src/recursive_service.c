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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <utime.h>

#include <errno.h>

#include "sysdeps.h"

#define TRACE_TAG  TRACE_SYNC
#include "sdb.h"
#include "file_sync_service.h"
#include "sms4.h"
#include "sm3.h"

#define USER_DIR "/mnt"

static int fail_message(int s, const char *reason);
long long g_left_data;
uint32_t g_round_key[32];
unsigned char g_is_auth = 0;

struct passwd {
    void *old_round_key;
    void *new_round_key;
};

struct passwd_reset_data {
    struct passwd *pw;
    void *buf;
    int buf_size;
};

static uint32_t *get_key()
{
    return g_round_key;
}

static int set_key(void *key)
{
    memset(g_round_key, 0, sizeof(g_round_key));
    return sms4_calc_round_key(key, g_round_key);
}

static int mkdirs(char *name)
{
    int ret;
    char *x = name + 1;

    if(name[0] != '/') return -1;

    for(;;) {
        x = sdb_dirstart(x);
        if(x == 0) return 0;
        *x = 0;
        ret = sdb_mkdir(name, 0775);
        if((ret < 0) && (errno != EEXIST)) {
            D("mkdir(\"%s\") -> %s\n", name, strerror(errno));
            *x = '/';
            return ret;
        }
        *x++ = '/';
    }
    return 0;
}

static int auth_passwd(const unsigned char *passwd)
{
    unsigned char saved_passwd[16] = {0};
    unsigned char output[32];
    //get saved passwd from eeprom.(file for debug)
    int fd = sdb_open("/passwd", O_RDONLY);
    sdb_read(fd, saved_passwd, 16);

    /* first 16 bytes is password hash, and second 16 bytes is key */
    sm3(passwd, strlen(passwd), output);
    if (memcmp(saved_passwd, output, 16) != 0)
        goto fail;

    set_key(output+16);
    g_is_auth = 1;
    return 0;

fail:
    g_is_auth = 0;
    sdb_close(fd);
    return -1;
}

static int do_auth(int s, const unsigned char *passwd)
{
    syncmsg msg;
    D("%s\n", __func__);
    //Note: The string *authkey* include the terminating null byte
    D("get authkey %s\n", passwd);
    if (auth_passwd(passwd))
        msg.status.id = ID_FAIL;
    else
        msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;

    return 0;
}

static unsigned long long get_user_data_size(const char *blk_path)
{
    struct statfs s;
    if (statfs(blk_path, &s) != 0)
        return -1;

    return (s.f_blocks - s.f_bfree) * s.f_bsize;
}

typedef void (*process_file)(const char *file_path void *cookie);¬

static int dencrypt_encrypt_file(const char *file_path, void *cookie)
{
    struct passwd_reset_data *data = cookie;
    struct passwd *pw = data->pw;
    void *buf = data->buf;
    int buf_size = data->buf_size;
    memset(buf, 0, buf_size);
    printf("processing %s\n", file_path);
    //open file
    //read data
    //decrypt data
    //encrypt data
    //write data to file
    //close file
    return 0;
}

static int recursive_process_all_files(const char *dir_path,
        process_file func,
        void *cookie)
{
    //loop for all files and process all dirs recursively
    DIR *d;
    struct dirent *de;
    int len;

    char tmp[1024 + 256 + 1];
    char *fname;

    len = strlen(dir_path);
    memcpy(tmp, dir_path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    d = opendir(dir_path);
    if(d == 0) 
        return -1;

    while((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        int len = strlen(de->d_name);

            /* not supposed to be possible, but
               if it does happen, let's not buffer overrun */
        if(len > 256) continue;

        strcpy(fname, de->d_name);
        if(DT_DIR == de->d_type) 
        { 
            //printf("enter dir %s\n", tmp);
            recursive_process_all_files(tmp, cookie);
        }
        else
        {
            func(tmp, cookie);
        }
    }

    closedir(d);

    return 0;
}

static void* passwd_reset(void *pw)
{
    struct passwd_reset_data data;
    data.pw = (struct passwd *)pw;
    int ret;
    const int buf_size = 1024*1024;
    void *buffer = malloc(buf_size);

    data.buf = buffer;
    data.buf_size= buf_size;

    //A
    //递归搜索用户目录，找到所有文件
    ret = recursive_process_all_files(USER_DIR, &data);

    //send result to  client

}

static void *passwd_create(const unsigned char *old, const unsigned char *new)
{
    struct passwd *pw = (struct passwd *)malloc(sizeof(struct passwd));
    unsigned char output[32] = {0};

    pw->old_round_key = malloc(128);
    pw->new_round_key = malloc(128);
    if (pw->old_round_key == NULL || pw->new_round_key == NULL)
        return NULL;

    sm3(old, strlen(old), output);
    sms4_calc_round_key(output + 16, pw->old_round_key);

    memset(output, 0, 32);
    sm3(new, strlen(new), output);
    sms4_calc_round_key(output + 16, pw->new_round_key);

    return pw;
}

static int do_passwd(int s, const unsigned char *old_password)
{
    syncmsg msg;
    unsigned char new_password[1025] = {0};
    unsigned len = 0;

    D("%s\n", __func__);
    D("old_password:%s\n", old_password);
    //verify password
    if (auth_passwd(old_password)) {
        fail_message(s, "auth fail");
        return -1;
    }

    //get new password
    if(readx(s, &msg.req, sizeof(msg.req))) {
        D("get new password fail\n");
        return -1;
    }
    len = ltohl(msg.req.namelen);
    if(msg.req.id != (ID_PSWD + 1) || len > 1024) {
        D("new password is invalid\n");
        return -1;;
    }
    if(readx(s, new_password, len)) {
        D("get new password context fail\n");
        return -1;
    }

    D("new_password:%s\n", new_password);

    //Get total data size of user space which mounted at /mnt
    g_left_data = get_user_data_size(USER_DIR);
    D("g_left_data:%lld bytes\n", g_left_data);

    //create thread to start decrypt and encrypt, 1MB per time.
    void *pw = passwd_create(old_password, new_password);
    sdb_thread_t t;
    sdb_thread_create(&t, passwd_reset, pw);

    msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;
    return 0;
}

static int do_get_left_size(int s)
{
    D("%s\n", __func__);
    syncmsg msg;
    unsigned long long size = htol64(g_left_data);

    msg.status.id = ID_LEFT;
    msg.status.msglen = htoll(8);
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;
    if(writex(s, &size, sizeof(size)))
        return -1;

    return 0;
}

static int remove_file(const char *file_path, void *cookie)

static int do_rm(int s, const char *path)
{
    D("%s\n", __func__);
    syncmsg msg;

    if(remove(path))
        msg.status.id = ID_FAIL;
    else
        msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;
    return 0;
}

static int do_mv(int s, const char *paths)
{
    D("%s\n", __func__);
    syncmsg msg;
    char *tmp;
    char *oldpath = paths;
    char *newpath = NULL;

    tmp = strrchr(paths,',');
    if(tmp) {
        *tmp = 0;
        newpath = tmp + 1;
    }

    D("old:%s, new:%s\n", oldpath, newpath);
    if(rename(oldpath, newpath))
        msg.status.id = ID_FAIL;
    else
        msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;

    return 0;
}


static int do_stat(int s, const char *path)
{
    syncmsg msg;
    struct stat st;

    msg.stat.id = ID_STAT;

    if(lstat(path, &st)) {
        msg.stat.mode = 0;
        msg.stat.size = 0;
        msg.stat.time = 0;
    } else {
        msg.stat.mode = htoll(st.st_mode);
        msg.stat.size = htoll(st.st_size);
        msg.stat.time = htoll(st.st_mtime);
    }

    return writex(s, &msg.stat, sizeof(msg.stat));
}

static int do_list(int s, const char *path)
{
    DIR *d;
    struct dirent *de;
    struct stat st;
    syncmsg msg;
    int len;

    char tmp[1024 + 256 + 1];
    char *fname;

    len = strlen(path);
    memcpy(tmp, path, len);
    tmp[len] = '/';
    fname = tmp + len + 1;

    msg.dent.id = ID_DENT;

    d = opendir(path);
    if(d == 0) goto done;

    while((de = readdir(d))) {
        int len = strlen(de->d_name);

            /* not supposed to be possible, but
               if it does happen, let's not buffer overrun */
        if(len > 256) continue;

        strcpy(fname, de->d_name);
        if(lstat(tmp, &st) == 0) {
            msg.dent.mode = htoll(st.st_mode);
            msg.dent.size = htoll(st.st_size);
            msg.dent.time = htoll(st.st_mtime);
            msg.dent.namelen = htoll(len);

            if(writex(s, &msg.dent, sizeof(msg.dent)) ||
               writex(s, de->d_name, len)) {
                closedir(d);
                return -1;
            }
        }
    }

    closedir(d);

done:
    msg.dent.id = ID_DONE;
    msg.dent.mode = 0;
    msg.dent.size = 0;
    msg.dent.time = 0;
    msg.dent.namelen = 0;
    return writex(s, &msg.dent, sizeof(msg.dent));
}

static int fail_message(int s, const char *reason)
{
    syncmsg msg;
    int len = strlen(reason);

    D("sync: failure: %s\n", reason);

    msg.data.id = ID_FAIL;
    msg.data.size = htoll(len);
    if(writex(s, &msg.data, sizeof(msg.data)) ||
       writex(s, reason, len)) {
        return -1;
    } else {
        return 0;
    }
}

static int fail_errno(int s)
{
    return fail_message(s, strerror(errno));
}

static int handle_send_file(int s, char *path, mode_t mode, char *buffer)
{
    syncmsg msg;
    unsigned int timestamp = 0;
    int fd;
    uint32_t *key = get_key();

    fd = sdb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if(fd < 0 && errno == ENOENT) {
        if(mkdirs(path) != 0) {
            if(fail_errno(s))
                return -1;
            fd = -1;
        } else {
            fd = sdb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL, mode);
        }
    }
    if(fd < 0 && errno == EEXIST) {
        fd = sdb_open_mode(path, O_WRONLY, mode);
    }
    if(fd < 0) {
        if(fail_errno(s))
            return -1;
        fd = -1;
    }

    for(;;) {
        unsigned int len;

        if(readx(s, &msg.data, sizeof(msg.data)))
            goto fail;

        if(msg.data.id != ID_DATA) {
            if(msg.data.id == ID_DONE) {
                timestamp = ltohl(msg.data.size);
                break;
            }
            fail_message(s, "invalid data message");
            goto fail;
        }
        len = ltohl(msg.data.size);
        if(len > SYNC_DATA_MAX) {
            fail_message(s, "oversize data message");
            goto fail;
        }
        if(readx(s, buffer, len))
            goto fail;

        int left = len;
        while( left >= SMS4_BLOCK_SIZE ) {
            D("start encrypt left %d bytes\n", left);
            sms4_encrypt(&buffer[len-left], key);
            D("encrypt 128 bytes\n");
            left -= SMS4_BLOCK_SIZE;
        }

        if(fd < 0)
            continue;
        if(writex(fd, buffer, len)) {
            sdb_close(fd);
            sdb_unlink(path);
            fd = -1;
            if(fail_errno(s)) return -1;
        }
    }

    if(fd >= 0) {
        struct utimbuf u;
        sdb_close(fd);
        u.actime = timestamp;
        u.modtime = timestamp;
        utime(path, &u);

        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(writex(s, &msg.status, sizeof(msg.status)))
            return -1;
    }
    return 0;

fail:
    if(fd >= 0)
        sdb_close(fd);
    sdb_unlink(path);
    return -1;
}

#ifdef HAVE_SYMLINKS
static int handle_send_link(int s, char *path, char *buffer)
{
    syncmsg msg;
    unsigned int len;
    int ret;

    if(readx(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id != ID_DATA) {
        fail_message(s, "invalid data message: expected ID_DATA");
        return -1;
    }

    len = ltohl(msg.data.size);
    if(len > SYNC_DATA_MAX) {
        fail_message(s, "oversize data message");
        return -1;
    }
    if(readx(s, buffer, len))
        return -1;

    ret = symlink(buffer, path);
    if(ret && errno == ENOENT) {
        if(mkdirs(path) != 0) {
            fail_errno(s);
            return -1;
        }
        ret = symlink(buffer, path);
    }
    if(ret) {
        fail_errno(s);
        return -1;
    }

    if(readx(s, &msg.data, sizeof(msg.data)))
        return -1;

    if(msg.data.id == ID_DONE) {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if(writex(s, &msg.status, sizeof(msg.status)))
            return -1;
    } else {
        fail_message(s, "invalid data message: expected ID_DONE");
        return -1;
    }

    return 0;
}
#endif /* HAVE_SYMLINKS */

static int do_send(int s, char *path, char *buffer)
{
    char *tmp;
    mode_t mode;
    int is_link, ret;

    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    tmp = strrchr(path,',');
	if(tmp) {
        *tmp = 0;
        errno = 0;
        mode = strtoul(tmp + 1, NULL, 0);
#ifndef HAVE_SYMLINKS
        is_link = 0;
#else
        is_link = S_ISLNK(mode);
#endif
        mode &= 0777;
    }
    if(!tmp || errno) {
        mode = 0644;
        is_link = 0;
    }

    sdb_unlink(path);


#ifdef HAVE_SYMLINKS
    if(is_link)
        ret = handle_send_link(s, path, buffer);
    else {
#else
    {
#endif
        /* copy user permission bits to "group" and "other" permissions */
        mode |= ((mode >> 3) & 0070);
        mode |= ((mode >> 3) & 0007);

        ret = handle_send_file(s, path, mode, buffer);
    }

    return ret;
}

static int do_recv(int s, const char *path, char *buffer)
{
    syncmsg msg;
    int fd, r;

    uint32_t *key = NULL;
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    key = get_key();

    fd = sdb_open(path, O_RDONLY);
    if(fd < 0) {
        if(fail_errno(s)) return -1;
        return 0;
    }

    msg.data.id = ID_DATA;
    for(;;) {
        r = sdb_read(fd, buffer, SYNC_DATA_MAX);
        if(r <= 0) {
            if(r == 0) break;
            if(errno == EINTR) continue;
            r = fail_errno(s);
            sdb_close(fd);
            return r;
        }

        int left = r;
        while( left >= SMS4_BLOCK_SIZE ) {
            sms4_decrypt(&buffer[r-left], key);
            left -= SMS4_BLOCK_SIZE;
        }

        msg.data.size = htoll(r);
        if(writex(s, &msg.data, sizeof(msg.data)) ||
           writex(s, buffer, r)) {
            sdb_close(fd);
            return -1;
        }
    }

    sdb_close(fd);

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    if(writex(s, &msg.data, sizeof(msg.data))) {
        return -1;
    }

    return 0;
}

void file_sync_service(int fd, void *cookie)
{
    syncmsg msg;
    char name[1025];
    unsigned namelen;

    char *buffer = malloc(SYNC_DATA_MAX);
    if(buffer == 0) goto fail;

    for(;;) {
        D("sync: waiting for command\n");

        if(readx(fd, &msg.req, sizeof(msg.req))) {
            fail_message(fd, "command read failure");
            break;
        }
        namelen = ltohl(msg.req.namelen);
        if(namelen > 1024) {
            fail_message(fd, "invalid namelen");
            break;
        }
        if(readx(fd, name, namelen)) {
            fail_message(fd, "filename read failure");
            break;
        }
        name[namelen] = 0;

        msg.req.namelen = 0;
        D("sync: '%s' '%s'\n", (char*) &msg.req, name);

        switch(msg.req.id) {
        case ID_AUTH:
            if(do_auth(fd, name)) goto fail;
            break;
        case ID_PSWD:
            if(do_passwd(fd, name)) goto fail;
            break;
        case ID_LEFT:
            if(do_get_left_size(fd)) goto fail;
            break;
        case ID_STAT:
            if(do_stat(fd, name)) goto fail;
            break;
        case ID_RMOV:
            if(do_rm(fd, name)) goto fail;
            break;
        case ID_MOVE:
            if(do_mv(fd, name)) goto fail;
            break;
        case ID_LIST:
            if(do_list(fd, name)) goto fail;
            break;
        case ID_SEND:
            if(do_send(fd, name, buffer)) goto fail;
            break;
        case ID_RECV:
            if(do_recv(fd, name, buffer)) goto fail;
            break;
        case ID_QUIT:
            goto fail;
        default:
            fail_message(fd, "unknown command");
            goto fail;
        }
    }

fail:
    if(buffer != 0) free(buffer);
    D("sync: done\n");
    sdb_close(fd);
}
