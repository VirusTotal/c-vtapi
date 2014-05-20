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

#define _GNU_SOURCE

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
#include <unistd.h>
#endif

#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <curl/curl.h>


#include "VtObject.h"
#include "VtApiPage.h"
#include "VtResponse.h"
#include "VtFileDist.h"

#include "vtcapi_common.h"

struct VtFileDist {
  API_OBJECT_COMMON;
  unsigned long long before;
  unsigned long long after;
  bool reports;
  int limit;
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtFileDist_constructor(struct VtObject *obj) {
  struct VtFileDist *vt_udist = (struct VtFileDist *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_udist);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtFileDist_destructor(struct VtObject *obj) {
  struct VtFileDist *vt_udist = (struct VtFileDist *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_udist);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtFileDist",
  .obj_size           = sizeof(struct VtFileDist),
  .obj_constructor    = VtFileDist_constructor,
  .obj_destructor     = VtFileDist_destructor,
// 	.obj_from_json      = VtFileDist_objectFromJSON,
};

static struct VtFileDist* VtFileDist_alloc(struct VtObject_ops *ops) {
  struct VtFileDist *FileScan;

  FileScan = (struct VtFileDist*) VtObject_alloc(ops);
  return FileScan;
}


struct VtFileDist* VtFileDist_new(void) {
  struct VtFileDist *FileScan = VtFileDist_alloc(&obj_ops);

  return FileScan;
}

/** Get a reference counter */
void VtFileDist_get(struct VtFileDist *obj) {
  VtObject_get((struct VtObject*) obj);
}

/** put a reference counter */
void VtFileDist_put(struct VtFileDist **obj) {
  VtApiPage_put((struct VtApiPage**) obj);
}

void VtFileDist_setApiKey(struct VtFileDist *vt_udist, const char *api_key) {
  // Call parent function
  return VtApiPage_setApiKey((struct VtApiPage *)vt_udist, api_key);
}

void VtFileDist_setReports(struct VtFileDist *vt_udist, bool value) {
  vt_udist->reports = value;
}

void VtFileDist_setAfter(struct VtFileDist *vt_udist, unsigned long long  value) {
  vt_udist->after = value;
}

void VtFileDist_setBefore(struct VtFileDist *vt_udist, unsigned long long  value) {
  vt_udist->before = value;
}

void VtFileDist_setLimit(struct VtFileDist *vt_udist, int value) {
  vt_udist->limit = value;
}

struct VtResponse * VtFileDist_getResponse(struct VtFileDist *vt_udist) {
  VtResponse_get(vt_udist->response);
  return vt_udist->response;
}

int VtFileDist_getDistribution(struct VtFileDist *vt_udist) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  char get_url[512];
  int len = 0;
  long http_response_code = 0;


  VtApiPage_resetBuffer((struct VtApiPage *) vt_udist);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  DBG(1, "Api Key =  '%s'\n", vt_udist->api_key);

  if (ret)
    VT_ERROR("Adding key\n");

  len = sprintf(get_url, VT_API_BASE_URL "file/distribution?apikey=%s", vt_udist->api_key);
  if (len < 0) {
    VT_ERROR("sprintf\n");
    goto cleanup;
  }

  if (vt_udist->before) {
    len += ret = sprintf(get_url + len, "&before=%lld", vt_udist->before);
    if (ret < 0) {
      VT_ERROR("sprintf before\n");
      goto cleanup;
    }
  }

  if (vt_udist->after) {
    len += ret = sprintf(get_url + len, "&after=%lld", vt_udist->after);
    if (ret < 0) {
      VT_ERROR("sprintf after\n");
      goto cleanup;
    }
  }

  if (vt_udist->reports) {
    len += ret = sprintf(get_url + len, "&reports=true");
    if (ret < 0) {
      VT_ERROR("sprintf after\n");
      goto cleanup;
    }
  }

  if (vt_udist->limit) {
    len += ret = sprintf(get_url + len, "&limit=%d", vt_udist->limit);
    if (ret < 0) {
      VT_ERROR("sprintf after\n");
      goto cleanup;
    }
  }
  DBG(1, "URL=%s\n", get_url);
  curl_easy_setopt(curl, CURLOPT_URL, get_url);

#ifdef DISABLE_HTTPS_VALIDATION
  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif



  /* enable verbose for easier tracing */
  if (debug_level)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_udist); // user arg


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
  DBG(1, "Page:\n%s\n",vt_udist->buffer);

  // if a previous response
  if (vt_udist->response)
    VtResponse_put(&vt_udist->response);   // relase reference counter

  vt_udist->response = VtResponse_new(); // new response object

  ret = VtResponse_fromJSONstr(vt_udist->response, vt_udist->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  return ret;
}

int VtFileDist_parse(struct VtFileDist* url_dist,
                     VtFileDistCb cb,
                     void *user_data) {
  json_t *resp_json, *file_jobj;
  json_t *url_str_json, *timestamp_json, *name_json, *sha256_json;
  int index;

  if (!url_dist || !url_dist->response) {
    VT_ERROR("No data recieved\n");
    return -1;
  }

  resp_json =  VtResponse_getJanssonObj(url_dist->response);

  if (!json_is_array(resp_json)) {
    VT_ERROR("JSON is not array\n");
    return -1;
  }

  json_array_foreach(resp_json, index, file_jobj) {

    if (!json_is_object(file_jobj)) {
      VT_ERROR("Parse error not a URL object\n");
      return -1;
    }

    url_str_json = json_object_get(file_jobj, "link");
    if (!url_str_json || !json_is_string(url_str_json)) {
      VT_ERROR("Parse error: link string\n");
      return -1;
    }
    name_json = json_object_get(file_jobj, "name");
    if (!name_json || !json_is_string(name_json)) {
      name_json = NULL;
    }
    sha256_json = json_object_get(file_jobj, "sha256");
    if (!sha256_json || !json_is_string(sha256_json)) {
      VT_ERROR("Parse error: sha256 string\n");
      return -1;
    }

    timestamp_json = json_object_get(file_jobj, "timestamp");
    if (!timestamp_json || !json_is_integer(timestamp_json)) {
      VT_ERROR("JSON parse error timestamp\n");
      return -1;
    }

    // set the after value, so if we do another query, we will not repeat the same data
    url_dist->after = json_integer_value(timestamp_json);

    // Call user defined callback function
    if (cb)
      cb(json_string_value(url_str_json), json_integer_value(timestamp_json),
         json_string_value(sha256_json), json_string_value(name_json),
         file_jobj, user_data);

  }

  return 0;
}

int VtFileDist_process(struct VtFileDist* url_dist,
                       void (*cb)(const char *url, unsigned long long timestamp, const char *sha256hash, const char *name, json_t *raw_json, void *data),
                       void *user_data) {
  int ret;

  ret = VtFileDist_getDistribution(url_dist);
  if (ret) {
    return ret;
  }

  return  VtFileDist_parse(url_dist, cb, user_data);
}

