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
#include "random_WNG4.h"

#define USER_DIR "/udisk"
#define  KEY_LEN 16

#define DEBUG_ENCRYPT 1
#if DEBUG_ENCRYPT
int g_debug_encrypt = 0;
#endif



long long g_left_data;
uint32_t g_round_key[32];
unsigned char g_is_auth = 0;
char *long_text = "When scientists look to the stars, they wonder about "
                    "their mystery. When we engineers look to the stars, "
                    "we think about building something to reach them. "
                    "To the stars and for engineering!!!!!!";

struct passwd {
    void *old_round_key;
    void *new_round_key;
};

static int fail_message(int s, const char *reason);

static uint32_t *get_roundkey()
{
    return g_round_key;
}

static void set_key(void *key)
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

static int auth_passwd(const char *passwd)
{
    unsigned char saved_key[KEY_LEN] = {0};
    unsigned char output[32];
    uint32_t  round_key[32];
    int fd = -1;
    size_t text_len = strlen(long_text);
    char *saved_text = calloc(1, text_len);
    int left;

    //get round key of protected key
    sm3((unsigned char*)passwd, strlen(passwd), output);
    sms4_calc_round_key((uint32_t *)output, round_key);

    fd = sdb_open("/mnt/cipher2", O_RDONLY);
    sdb_read(fd, saved_text, text_len);
    sdb_close(fd);

    left = text_len;
    while( left >= SMS4_BLOCK_SIZE  )
    {
        sms4_decrypt(&saved_text[text_len - left], round_key);
        left -= SMS4_BLOCK_SIZE;
    }

    if( memcmp(saved_text, long_text, text_len) != 0) 
        goto fail;

    free(saved_text);

    //get saved passwd from file
    fd = sdb_open("/mnt/cipher1", O_RDONLY);
    sdb_read(fd, saved_key, KEY_LEN);
    sdb_close(fd);

    /* The length of sm3 hash value is 32 bytes, but sms4 key only use first 16B*/
    sms4_decrypt(saved_key, round_key);

    set_key(saved_key);
    g_is_auth = 1;
    return 0;

fail:
    if (saved_text)
        free(saved_text);
    g_is_auth = 0;
    return -1;

}

static int do_auth(int s, const char *passwd)
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

#if 0
static unsigned long long get_user_data_size(const char *blk_path)
{
    struct statfs s;
    if (statfs(blk_path, &s) != 0)
        return -1;

    return (s.f_blocks - s.f_bfree) * s.f_bsize;
}
#endif

static int passwd_change(const char *old, const char *new)
{
    unsigned char save_key[KEY_LEN] = {0};
    unsigned char output[32] = {0};
    uint32_t old_round_key[32] = {0};
    uint32_t new_round_key[32] = {0};
    int fd = -1;
    size_t text_len = strlen(long_text);
    char *save_text = calloc(1, text_len);
    int left;

    memcpy(save_text, long_text, text_len);

    sm3((unsigned char*)old, strlen(old), output);
    sms4_calc_round_key((uint32_t *)output, old_round_key);
    sm3((unsigned char*)new, strlen(new), output);
    sms4_calc_round_key((uint32_t*)output, new_round_key);

    left = text_len;
    while (left >= SMS4_BLOCK_SIZE) {
        sms4_encrypt(&save_text[text_len - left], new_round_key);
        left -= SMS4_BLOCK_SIZE;
    }

    fd = sdb_open("/mnt/cipher2", O_WRONLY|O_SYNC);
    sdb_write(fd, save_text, text_len);
    sdb_close(fd);
    free(save_text);

    fd = sdb_open("/mnt/cipher1", O_RDWR|O_SYNC);

    //TODO:error process
    sdb_read(fd, save_key, KEY_LEN);

    /* The length of sm3 hash value is 32 bytes, but sms4 key only use first 16B*/
    sms4_decrypt(save_key, old_round_key);
    sms4_encrypt(save_key, new_round_key);

    sdb_lseek(fd, 0, SEEK_SET);
    sdb_write(fd, save_key, KEY_LEN);
    sdb_close(fd);

    return 0;

fail:
    return -1;
}

static int do_passwd(int s, const char *old_password)
{
    syncmsg msg;
    char new_password[1025] = {0};
    unsigned len = 0;

    D("%s, old_password:%s\n", __func__, old_password);
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

    //create thread to start decrypt and encrypt, 1MB per time.
    passwd_change(old_password, new_password);

    msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;
    return 0;
}

#if 0 //discard
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
#endif

static int remove_dir(const char *dir_path)
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
        if(len > 256) continue;

        strcpy(fname, de->d_name);
        if(DT_DIR == de->d_type) 
            remove_dir(tmp);
        else
            sdb_unlink(tmp);
    }

    closedir(d);
    rmdir(dir_path);

    return 0;
}


static int do_rm(int s, const char *path)
{
    D("func:%s, path:%s\n", __func__, path);
    syncmsg msg;
    struct stat st;
    int r;

 #if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

   lstat(path, &st);
    if (S_ISDIR(st.st_mode))
        r = remove_dir(path);
    else
        r = sdb_unlink(path);

    if(r)
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
    D("func:%s, paths:%s\n", __func__, paths);
    syncmsg msg;
    char *tmp;
    char oldpath[1025] = {0};
    char newpath[1024] = {0};

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    tmp = strrchr(paths,',');
    if(tmp) {
        *tmp = 0;
        sprintf(oldpath, USER_DIR"/%s", paths);
        sprintf(newpath, USER_DIR"/%s", tmp + 1);
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

static int do_cp(int s, const char *paths)
{
    D("func:%s, paths:%s\n", __func__, paths);
    syncmsg msg;
    char *seq;
    char oldpath[1025] = {0};
    char newpath[1025] = {0};
    char cmd[2064] = {0};
    FILE *fp = NULL;
    char tmp[512] = {0};
    char *errmsg = tmp;

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    seq = strrchr(paths,',');
    if(seq) {
        *seq = 0;
        sprintf(oldpath, USER_DIR"/%s", paths);
        sprintf(newpath, USER_DIR"/%s", seq + 1);
    }

    sprintf(cmd, "/bin/busybox cp -a %s %s 2>&1", oldpath, newpath);
    D("cmd %s\n", cmd);

    fp = popen(cmd, "r");
    if (NULL == fp) {
        msg.status.id = ID_FAIL;
        sprintf(errmsg, "Unknown reason");
        msg.status.msglen = strlen(errmsg);
        goto fail;
    }

    fgets(tmp, sizeof(tmp)-1, fp);

    if(strlen(errmsg) > 0) {
        errmsg = strrchr(tmp, ':');
        if (NULL == errmsg)
            errmsg = tmp;
        else
            errmsg++;

        msg.status.id = ID_FAIL;
        msg.status.msglen = strlen(errmsg);
        D("error:%s\n", tmp);
    } else {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
    }

    pclose(fp);

fail:
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;

    if (msg.status.msglen > 0)
        if(writex(s, errmsg, msg.status.msglen))
            return -1;

    return 0;
}

static int do_umount(int s)
{
    D("func:%s\n", __func__);
    syncmsg msg;
    FILE *fp;
    char tmp[512] = {0};
    char *errmsg = tmp;

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    fp = popen("/bin/umount /udisk 2>&1", "r");
    if (NULL == fp) {
        msg.status.id = ID_FAIL;
        sprintf(errmsg, "Unknown");
        msg.status.msglen = strlen(errmsg);
        goto fail;
    }

    fgets(tmp, sizeof(tmp)-1, fp);

    if(strlen(errmsg) > 0) {
        errmsg = strrchr(tmp, ':');
        if (NULL == errmsg)
            errmsg = tmp;
        else
            errmsg++;

        msg.status.id = ID_FAIL;
        msg.status.msglen = strlen(errmsg);
    } else {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
    }

    pclose(fp);

fail:
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;

    if (msg.status.msglen > 0)
        if(writex(s, errmsg, msg.status.msglen))
            return -1;

    return 0;
}

static int do_reset(int s)
{
    D("func:%s\n", __func__);
    syncmsg msg;
    FILE *fp;
    char tmp[512] = {0};
    char *errmsg = tmp;

    fp = popen("/mnt/tools/factory_reset", "r");
    if (NULL == fp) {
        msg.status.id = ID_FAIL;
        sprintf(errmsg, "Unknown");
        msg.status.msglen = strlen(errmsg);
        goto fail;
    }

    fgets(tmp, sizeof(tmp)-1, fp);

    if(strlen(errmsg) > 0) {
        errmsg = strrchr(tmp, ':');
        if (NULL == errmsg)
            errmsg = tmp;
        else
            errmsg++;

        msg.status.id = ID_FAIL;
        msg.status.msglen = strlen(errmsg);
    } else {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
    }

    pclose(fp);

fail:
    if(writex(s, &msg.status, sizeof(msg.status)))
        return -1;

    if (msg.status.msglen > 0)
        if(writex(s, errmsg, msg.status.msglen))
            return -1;

    return 0;
}

static int do_stat(int s, const char *path)
{
    D("func:%s, path:%s\n", __func__, path);
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
    D("func:%s, path:%s\n", __func__, path);
    DIR *d;
    struct dirent *de;
    struct stat st;
    syncmsg msg;
    int len;

    char tmp[1024 + 256 + 1];
    char *fname;

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

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

static int file_tail_encrypt(int fd, char *tail, unsigned int tail_len)
{
    uint32_t *key = get_roundkey();
    char buffer[SMS4_BLOCK_SIZE + 1] = {0};
    char padding = SMS4_BLOCK_SIZE - tail_len + 1;
    int i;

    if (fd < 0)
        return fd;

    if (0 == tail_len) {
        buffer[0] = 1; //padding num
        if(writex(fd, buffer, 1)) {
            sdb_close(fd);
            fd = -1;
        }
        return fd;
    }

    //file the last block
    memcpy(buffer, tail, tail_len);
    enable_WNG4();
    for (i = 0; i < padding - 1; i++)
        buffer[tail_len + i] = get_byte_random();
    disable_WNG4();
    buffer[SMS4_BLOCK_SIZE] = padding;
    //D("tail bytes:%d, tail_len:%d\n", padding, tail_len);

    sdb_lseek(fd, -tail_len, SEEK_END);
    sms4_encrypt(buffer, key);
    if(writex(fd, buffer, SMS4_BLOCK_SIZE + 1)) {
        sdb_close(fd);
        fd = -1;
    }
    return fd;
}

static int handle_send_file(int s, char *path, mode_t mode, char *buffer)
{
    syncmsg msg;
    unsigned int timestamp = 0;
    int fd;
    uint32_t *key = get_roundkey();
    unsigned int len = 0;

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

        if(readx(s, &msg.data, sizeof(msg.data)))
            goto fail;

        if(msg.data.id != ID_DATA) {
            if(msg.data.id == ID_DONE) {
                //Encrypt the tail of file
                fd = file_tail_encrypt(fd,
                        buffer + len - len % SMS4_BLOCK_SIZE,
                        len % SMS4_BLOCK_SIZE);
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

#if DEBUG_ENCRYPT
        if (g_debug_encrypt) {
#endif
        int left = len;
        while( left >= SMS4_BLOCK_SIZE ) {
            sms4_encrypt(&buffer[len-left], key);
            left -= SMS4_BLOCK_SIZE;
        }
#if DEBUG_ENCRYPT
        }
#endif
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
    D("func:%s, path:%s\n", __func__, path);
    char *tmp;
    mode_t mode;
    int is_link, ret;

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
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
    D("func:%s, path:%s\n", __func__, path);
    syncmsg msg;
    int fd, r;
    uint32_t *key = NULL;
    int file_size = 0;
    char padding = 0;
    int cur = 0;

#if DEBUG_ENCRYPT
    if (g_debug_encrypt)
#endif
    if (!g_is_auth) {
        fail_message(s, "Authentication fail");
        return -1;
    }

    key = get_roundkey();

    fd = sdb_open(path, O_RDONLY);
    if(fd < 0) {
        if(fail_errno(s)) return -1;
        return 0;
    }

    //get file size, and padding bytes.
    file_size = sdb_lseek(fd, 0, SEEK_END);
    sdb_lseek(fd, -1, SEEK_END);
    readx(fd, &padding, 1);
    sdb_lseek(fd, 0, SEEK_SET);

    msg.data.id = ID_DATA;
    for(;;) {
        r = sdb_read(fd, buffer, SYNC_DATA_MAX);
        if(r <= 0) {
            if(r == 0 || r == 1)
                break;
            if(errno == EINTR) continue;
            r = fail_errno(s);
            sdb_close(fd);
            return r;
        }

#if DEBUG_ENCRYPT
        if (g_debug_encrypt) {
#endif
        int left = r;
        while( left >= SMS4_BLOCK_SIZE ) {
            sms4_decrypt(&buffer[r-left], key);
            left -= SMS4_BLOCK_SIZE;
        }
#if DEBUG_ENCRYPT
        }
#endif

        //When left is 1, it must be padding num in the file end
        cur += r;
        if (file_size == cur) {
            r -= padding;
            if (r < 0)
                r = 0;
        }
        else if (1 == file_size - cur)
            r -= (padding - 1);

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

static inline void build_user_path(char *path)
{
    memmove(path + strlen(USER_DIR), path, strlen(path) + 1);
    memcpy(path, USER_DIR, strlen(USER_DIR));
}

void file_sync_service(int fd, void *cookie)
{
    syncmsg msg;
    char name[1025] = {0};
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
        if(namelen > 1024 -  sizeof(USER_DIR)) {
            fail_message(fd, "invalid path length");
            break;
        }
        if(readx(fd, name, namelen)) {
            fail_message(fd, "filename read failure");
            break;
        }
        name[namelen] = 0;

        msg.req.namelen = 0;
        D("sync: '%s' '%s'\n", (char*) &msg.req, name);

#if DEBUG_ENCRYPT
        g_debug_encrypt = 1;
#endif

        switch(msg.req.id) {
        case ID_AUTH:
            if(do_auth(fd, name)) goto fail;
            break;
        case ID_PSWD:
            if(do_passwd(fd, name)) goto fail;
            break;
#if 0 //discard
        case ID_LEFT:
            if(do_get_left_size(fd)) goto fail;
            break;
#endif
        case ID_STAT:
            build_user_path(name);
            if(do_stat(fd, name)) goto fail;
            break;
        case ID_RMOV:
            build_user_path(name);
            if(do_rm(fd, name)) goto fail;
            break;
        case ID_MOVE:
            //Modify path prefix in function
            if(do_mv(fd, name)) goto fail;
            break;
        case ID_COPY:
            if(do_cp(fd, name)) goto fail;
            break;
        case ID_UMNT:
            if(do_umount(fd)) goto fail;
            break;
        case ID_REST:
            if(do_reset(fd)) goto fail;
            break;
        case ID_LIST:
            build_user_path(name);
            if(do_list(fd, name)) goto fail;
            break;
        case ID_SEND:
            build_user_path(name);
            if(do_send(fd, name, buffer)) goto fail;
            break;
        case ID_RECV:
            build_user_path(name);
            if(do_recv(fd, name, buffer)) goto fail;
            break;
#if DEBUG_ENCRYPT
        case ID_SERA:
            g_debug_encrypt = 0;
            build_user_path(name);
            if(do_send(fd, name, buffer)) goto fail;
            break;
        case ID_RERA:
            g_debug_encrypt = 0;
            build_user_path(name);
            if(do_recv(fd, name, buffer)) goto fail;
            break;
#endif
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
