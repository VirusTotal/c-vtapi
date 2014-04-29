/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


#ifdef HAVE_CONFIG_H
#include "c-vtapi_config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <pthread.h>
#include <unistd.h>
#endif

#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <errno.h>


#include "VtObject.h"
#include "VtApiPage.h"
#include "VtResponse.h"

#include "vtcapi_common.h"


/**
 * @struct VtFile
 * @brief A file object
 */
struct VtFile {
  API_OBJECT_COMMON;
  char *offset; // offset for use in search
  bool cancel_operation;
  int64_t dltotal;
  int64_t dlnow;
  int64_t ultotal;
  int64_t ulnow;
  void *progress_cb_data;
  int (*progress_changed_cb)(struct VtFile *,  void *);
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtFile_constructor(struct VtObject *obj) {
  struct VtFile *file_scan = (struct VtFile *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", file_scan);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtFile_destructor(struct VtObject *obj) {
  struct VtFile *file_scan = (struct VtFile *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", file_scan);

  if (file_scan->offset)
    free(file_scan->offset);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "file/scan",
  .obj_size           = sizeof(struct VtFile),
  .obj_constructor    = VtFile_constructor,
  .obj_destructor     = VtFile_destructor,
};

static struct VtFile* VtFile_alloc(struct VtObject_ops *ops) {
  struct VtFile *FileScan;

  FileScan = (struct VtFile*) VtObject_alloc(ops);
  return FileScan;
}


struct VtFile* VtFile_new(void) {
  struct VtFile *FileScan = VtFile_alloc(&obj_ops);

  return FileScan;
}

/** Get a reference counter */
void VtFile_get(struct VtFile *FileScan) {
  VtObject_get((struct VtObject*) FileScan);
}

/** put a reference counter */
void VtFile_put(struct VtFile **FileScan) {
  VtApiPage_put((struct VtApiPage**) FileScan);
}



void VtFile_setApiKey(struct VtFile *file_scan, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)file_scan, api_key);
}


void VtFile_setOffset(struct VtFile *file_scan, const char *offset) {
  if (file_scan->offset) {
    free(file_scan->offset);
  }
  if (offset)
    file_scan->offset = strdup(offset);
  else
    file_scan->offset = NULL;
}


struct VtResponse * VtFile_getResponse(struct VtFile *file_scan) {
  VtResponse_get(file_scan->response);
  return file_scan->response;
}

void VtFile_setProgressCallback(struct VtFile *file,
    int (*progress_changed_cb)(struct VtFile *, void *), void *data)
{
  file->progress_cb_data = data;
  file->progress_changed_cb = progress_changed_cb;
}

/* curl progress data for CURLOPT_XFERINFOFUNCTION callback  */
static int xferinfo(void *p,
                    curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
  struct VtFile *file = (struct VtFile *)p;

  DBG(1, "UP: %" CURL_FORMAT_CURL_OFF_T " of %" CURL_FORMAT_CURL_OFF_T
         "  DOWN: %" CURL_FORMAT_CURL_OFF_T " of %" CURL_FORMAT_CURL_OFF_T
         "\r\n",
         ulnow, ultotal, dlnow, dltotal);

  VT_OBJECT_LOCK(file);
  file->dltotal = dltotal;
  file->dlnow = dlnow;
  file->ultotal = ultotal;
  file->ulnow = ulnow;
  VT_OBJECT_UNLOCK(file);

  if(file->cancel_operation)
    return 1;

  if (file->progress_changed_cb)
    file->progress_changed_cb(file, file->progress_cb_data);
  return 0;
}

/* for libcurl older than 7.32.0 (CURLOPT_PROGRESSFUNCTION) */
static int older_progress(void *p,
                          double dltotal, double dlnow,
                          double ultotal, double ulnow)
{
  return xferinfo(p,
                  (curl_off_t)dltotal,
                  (curl_off_t)dlnow,
                  (curl_off_t)ultotal,
                  (curl_off_t)ulnow);
}


void VtFile_getProgress(struct VtFile *file, int64_t *dltotal, int64_t *dlnow, int64_t *ul_total, int64_t *ul_now)
{
  VT_OBJECT_LOCK(file);
  *dltotal = file->dltotal;
  *dlnow = file->dlnow;
  *ul_total = file->ulnow;
  *ul_now = file->ulnow;
  VT_OBJECT_UNLOCK(file);
}

void VtFile_cancelOperation(struct VtFile* file) {
  file->cancel_operation = true;
}

static void set_std_curl_data(struct VtFile *file, CURL *curl)
{

  curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, older_progress);
  /* pass the struct pointer into the progress function */
  curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, file);

  #if LIBCURL_VERSION_NUM >= 0x072000
  /* xferinfo was introduced in 7.32.0, no earlier libcurl versions will
   * compile as they won't have the symbols around.
   *
   * If built with a newer libcurl, but running with an older libcurl:
   * curl_easy_setopt() will fail in run-time trying to set the new
   * callback, making the older callback get used.
   *
   * New libcurls will prefer the new callback and instead use that one even
   * if both callbacks are set. */

  curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
  /* pass the struct pointer into the xferinfo function, note that this is
   * an alias to CURLOPT_PROGRESSDATA */
  curl_easy_setopt(curl, CURLOPT_XFERINFODATA, file);
  #endif

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

  #ifdef DISABLE_HTTPS_VALIDATION
  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  #endif

  /* enable verbose for easier tracing */
  if (debug_level)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, file); // user arg

}

int VtFile_scan(struct VtFile *file_scan, const char *file_path) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char header_buf[] = "Expect:";


  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);

  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "File to send '%s'\n", file_path);
  DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "file",
                     CURLFORM_FILE,  file_path,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding file %s\n", file_path);

  /* Fill in the filename field */
  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "filename",
                     CURLFORM_COPYCONTENTS, file_path, // FIXME
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding filename %s\n", file_path);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "apikey",
                     CURLFORM_COPYCONTENTS, file_scan->api_key,
                     CURLFORM_END);

  if (ret)
    VT_ERROR("Adding key\n");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/scan");

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

  set_std_curl_data(file_scan, curl);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);

  if (file_scan->response)
    VtResponse_put(&file_scan->response);

  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  if (formpost)
    curl_formfree(formpost);  // cleanup the formpost chain

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}


int VtFile_rescanHash(struct VtFile *file_scan,
                      const char *hash,
                      time_t rescan_date, int period, int repeat,
                      const char *notify_url, bool notify_changes_only) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  char buff[32];
  struct tm time_result;
  static const char header_buf[] = "Expect:";

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);

  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "hash to rescan'%s'\n", hash);
  DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "resource",
                     CURLFORM_COPYCONTENTS,  hash,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding hash %s\n", hash);

  if (rescan_date) {
#ifdef WINDOWS
    if (!gmtime_s(&time_result, &rescan_date)) {
      VT_ERROR("Converting time\n");
      goto cleanup;
    }
#else
    if (!gmtime_r(&rescan_date, &time_result)) {
      VT_ERROR("Converting time\n");
      goto cleanup;
    }
#endif

    ret = strftime(buff, sizeof(buff)-1, "%Y%m%d%H%M%S", &time_result);
    ret = curl_formadd(&formpost,
                       &lastptr,
                       CURLFORM_COPYNAME, "date",
                       CURLFORM_COPYCONTENTS,  buff,
                       CURLFORM_END);
    if (ret)
      VT_ERROR("Adding date %s\n", buff);
  }

  if (period) {
    snprintf(buff, sizeof(buff) -1, "%d", period);
    ret = curl_formadd(&formpost,
                       &lastptr,
                       CURLFORM_COPYNAME, "period",
                       CURLFORM_COPYCONTENTS,  buff,
                       CURLFORM_END);
    if (ret)
      VT_ERROR("Adding period %s\n", buff);
  }

  if (repeat) {
    snprintf(buff, sizeof(buff) - 1 , "%d", repeat);
    ret = curl_formadd(&formpost,
                       &lastptr,
                       CURLFORM_COPYNAME, "repeat",
                       CURLFORM_COPYCONTENTS,  buff,
                       CURLFORM_END);
    if (ret)
      VT_ERROR("Adding repeat %s\n", buff);
  }

  if (notify_url) {
    ret = curl_formadd(&formpost,
                       &lastptr,
                       CURLFORM_COPYNAME, "notify_url",
                       CURLFORM_COPYCONTENTS,  notify_url,
                       CURLFORM_END);
    if (ret)
      VT_ERROR("Adding notify_url %s\n", notify_url);

    if (notify_changes_only) {
      ret = curl_formadd(&formpost,
                         &lastptr,
                         CURLFORM_COPYNAME, "notify_changes_only",
                         CURLFORM_COPYCONTENTS,  "1",
                         CURLFORM_END);
    }
  }


  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "apikey",
                     CURLFORM_COPYCONTENTS, file_scan->api_key,
                     CURLFORM_END);

  if (ret)
    VT_ERROR("Adding key\n");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/rescan");

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

  set_std_curl_data(file_scan, curl);


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);
  if (file_scan->response)
    VtResponse_put(&file_scan->response);

  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  if (formpost)
    curl_formfree(formpost);  // cleanup the formpost chain

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}

int VtFile_rescanDelete(struct VtFile *file_scan,
                        const char *hash) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char header_buf[] = "Expect:";

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);

  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "hash to rescan'%s'\n", hash);
  DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "resource",
                     CURLFORM_COPYCONTENTS,  hash,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding hash %s\n", hash);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "apikey",
                     CURLFORM_COPYCONTENTS, file_scan->api_key,
                     CURLFORM_END);

  if (ret)
    VT_ERROR("Adding key\n");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/rescan/delete");

  set_std_curl_data(file_scan, curl);

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);
  if (file_scan->response)
    VtResponse_put(&file_scan->response);

  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  if (formpost)
    curl_formfree(formpost);  // cleanup the formpost chain

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}


int VtFile_report(struct VtFile *file_scan, const char *hash) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char header_buf[] = "Expect:";
  long http_response_code = 0;

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "hash to rescan'%s'\n", hash);
  DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "resource",
                     CURLFORM_COPYCONTENTS,  hash,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding hash %s\n", hash);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "apikey",
                     CURLFORM_COPYCONTENTS, file_scan->api_key,
                     CURLFORM_END);

  if (ret)
    VT_ERROR("Adding key\n");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/report");

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

  set_std_curl_data(file_scan, curl);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    if (http_response_code != 200) {
      VT_ERROR("HTTP Response code: %ld\n", http_response_code);
      ret = http_response_code;
      goto cleanup;
    }
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);

  if (file_scan->response)
    VtResponse_put(&file_scan->response);
  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  if (formpost)
    curl_formfree(formpost);  // cleanup the formpost chain

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}


int VtFile_search(struct VtFile *file_scan, const char *query,
                  void (*cb)(const char *resource, void *data),
                  void *user_data) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  json_t *resp_json = NULL;
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char header_buf[] = "Expect:";
  long http_response_code = 0;

  if (!query || !query[0]) {
    VT_ERROR("search query can not be empty\n");
    return -1;
  }

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "query",
                     CURLFORM_COPYCONTENTS,  query,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding qury %s\n", query);

  ret = curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "apikey",
                     CURLFORM_COPYCONTENTS, file_scan->api_key,
                     CURLFORM_END);
  if (ret)
    VT_ERROR("Adding key\n");



  if (file_scan->offset) {
    ret = curl_formadd(&formpost,
                       &lastptr,
                       CURLFORM_COPYNAME, "offset",
                       CURLFORM_COPYCONTENTS, file_scan->offset,
                       CURLFORM_END);
    if (ret)
      VT_ERROR("Adding offset\n");

  }

// 	DBG(1, "URL=%s \n", url);
  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/search");

  set_std_curl_data(file_scan, curl);

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    if (http_response_code != 200) {
      VT_ERROR("HTTP Response code: %ld\n", http_response_code);
      ret = http_response_code;
      goto cleanup;
    }
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);

  if (file_scan->response)
    VtResponse_put(&file_scan->response);
  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }
  resp_json =  VtResponse_getJanssonObj(file_scan->response);

  if (resp_json) {
    json_t *offset_json = json_object_get(resp_json, "offset");
    if (json_is_string(offset_json)) {
      VtFile_setOffset(file_scan, json_string_value(offset_json));
    }
  }

  if (cb && resp_json) {
    json_t *hashes_json = json_object_get(resp_json, "hashes");
    unsigned int index;
    json_t *hash_obj;
    json_t *offset_json = json_object_get(resp_json, "offset");

    if (offset_json && json_is_string(offset_json)
        && json_string_value(offset_json) && json_string_value(offset_json)[0]) {
      VtFile_setOffset(file_scan, json_string_value(offset_json));
    }

    if (!hashes_json || !json_is_array(hashes_json)) {
      VT_ERROR("Parse error: hashes\n");
      goto cleanup;
    }

    json_array_foreach(hashes_json, index, hash_obj) {
      if (!json_is_string(hash_obj)) {
        VT_ERROR("hash is not string\n");
        continue;
      }
      cb(json_string_value(hash_obj), user_data);
    }
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  if (formpost)
    curl_formfree(formpost);  // cleanup the formpost chain

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

// 	if (query_escaped)
// 		curl_free(query_escaped);


  return ret;
}



int VtFile_clusters(struct VtFile *file_scan, const char *cluster_date,
                    void (*cb)(json_t *cluster_json, void *data), void *user_data) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  json_t *resp_json = NULL;
  long http_response_code = 0;
  char url[1024];

  if (!cluster_date || !cluster_date[0]) {
    VT_ERROR("search cluster_date can not be empty\n");
    return -1;
  }

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  snprintf(url, sizeof(url) - 1 , VT_API_BASE_URL "file/clusters?apikey=%s&date=%s",
           file_scan->api_key, cluster_date);
// 	DBG(1, "URL=%s \n", url);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  set_std_curl_data(file_scan, curl);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    if (http_response_code != 200) {
      VT_ERROR("HTTP Response code: %ld\n", http_response_code);
      ret = http_response_code;
      goto cleanup;
    }
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);

  if (file_scan->response)
    VtResponse_put(&file_scan->response);
  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

  resp_json =  VtResponse_getJanssonObj(file_scan->response);

  if (resp_json) {
    json_t *offset_json = json_object_get(resp_json, "offset");
    if (json_is_string(offset_json)) {
      VtFile_setOffset(file_scan, json_string_value(offset_json));
    }
  }

  if (cb && resp_json) {
    json_t *clusters_json = json_object_get(resp_json, "clusters");
    unsigned int index;
    json_t *cl_json = NULL;


    if (!clusters_json || !json_is_array(clusters_json)) {
      goto cleanup;
    }

    json_array_foreach(clusters_json, index, cl_json) {
      if (!json_is_object(cl_json)) {
        VT_ERROR("not valid object\n");
        continue;
      }
      cb(cl_json, user_data);
    }
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);


  return ret;
}

// Example data structure that can be passed to callback function
/**
 * @brief Download callback data
 *
 */
struct DlCallbackData {
  int counter;
  FILE *fp;
};


int VtFile_download(struct VtFile *file_scan, const char *hash,
                    size_t (*cb)(char *ptr, size_t size, size_t nmemb, void *userdata), void *user_data) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  long http_response_code = 0;
  char url[1024];


  if (!hash || !hash[0]) {
    VT_ERROR("search hash can not be empty\n");
    return -1;
  }

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  snprintf(url, sizeof(url) - 1, VT_API_BASE_URL "file/download?apikey=%s&hash=%s",
           file_scan->api_key, hash);
  DBG(1, "URL=%s \n", url);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  set_std_curl_data(file_scan, curl);


  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // download API will redirect to link

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, user_data); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
    if (http_response_code != 200 && http_response_code != 302) {
      VT_ERROR("HTTP Response code: %ld\n", http_response_code);
      ret = http_response_code;
      goto cleanup;
    }
  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);


cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);


  return ret;
}

static size_t download_to_file_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  struct DlCallbackData * cb_data = (struct DlCallbackData *) userdata;
  int sz;

  sz = fwrite(ptr, size, nmemb, cb_data->fp);

  DBG(1, "Wrote %d bytes\n", sz);
  return sz;
}

int VtFile_downloadToFile(struct VtFile *file_scan, const char *hash, const char *out_file) {
  struct DlCallbackData cb_data = { .counter = 0, .fp = NULL };
  int ret;

  DBG(1, "hash=%s  out_file=%s\n", hash, out_file);

  cb_data.fp = fopen(out_file, "w+");
  if (!cb_data.fp) {
    VT_ERROR("Createing output file %s\n", out_file);
    return -errno;
  }
  ret = VtFile_download(file_scan, hash, download_to_file_cb, &cb_data);

  fclose(cb_data.fp);
  return ret;
}


int VtFile_uploadUrl(struct VtFile *file_scan, char **url) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  json_t *resp_json = NULL;
  char get_url[768];

  VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  ret = snprintf(get_url, sizeof(get_url)-1,
                 VT_API_BASE_URL "file/scan/upload_url?apikey=%s",
                 file_scan->api_key);

  curl_easy_setopt(curl, CURLOPT_URL, get_url);

  set_std_curl_data(file_scan, curl);


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  } else  {

  }

  DBG(1, "Page:\n%s\n",file_scan->buffer);

  if (file_scan->response)
    VtResponse_put(&file_scan->response);
  file_scan->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }
  resp_json =  VtResponse_getJanssonObj(file_scan->response);

  if (resp_json) {
    json_t *url_json = json_object_get(resp_json, "upload_url");
    if (json_is_string(url_json)) {
      *url = strdup(json_string_value(url_json));
    }
  }

cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  return ret;
}


