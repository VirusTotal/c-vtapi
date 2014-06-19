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

#include "vtcapi_common.h"

struct VtUrlDist {
  API_OBJECT_COMMON;
  unsigned long long before;
  unsigned long long after;
  bool allinfo;
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
int VtUrlDist_constructor(struct VtObject *obj) {
  struct VtUrlDist *vt_udist = (struct VtUrlDist *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_udist);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtUrlDist_destructor(struct VtObject *obj) {
  struct VtUrlDist *vt_udist = (struct VtUrlDist *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_udist);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtUrlDist",
  .obj_size           = sizeof(struct VtUrlDist),
  .obj_constructor    = VtUrlDist_constructor,
  .obj_destructor     = VtUrlDist_destructor,
// 	.obj_from_json      = VtUrlDist_objectFromJSON,
};

static struct VtUrlDist* VtUrlDist_alloc(struct VtObject_ops *ops) {
  struct VtUrlDist *FileScan;

  FileScan = (struct VtUrlDist*) VtObject_alloc(ops);
  return FileScan;
}


struct VtUrlDist* VtUrlDist_new(void) {
  struct VtUrlDist *FileScan = VtUrlDist_alloc(&obj_ops);

  return FileScan;
}

/** Get a reference counter */
void VtUrlDist_get(struct VtUrlDist *obj) {
  VtObject_get((struct VtObject*) obj);
}

/** put a reference counter */
void VtUrlDist_put(struct VtUrlDist **obj) {
  VtApiPage_put((struct VtApiPage**) obj);
}

void VtUrlDist_setApiKey(struct VtUrlDist *vt_udist, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)vt_udist, api_key);
}

void VtUrlDist_setAllInfo(struct VtUrlDist *vt_udist, bool value) {
  vt_udist->allinfo = value;
}

void VtUrlDist_setAfter(struct VtUrlDist *vt_udist, unsigned long long  value) {
  vt_udist->after = value;
}

void VtUrlDist_setBefore(struct VtUrlDist *vt_udist, unsigned long long  value) {
  vt_udist->before = value;
}

void VtUrlDist_setLimit(struct VtUrlDist *vt_udist, int value) {
  vt_udist->limit = value;
}

struct VtResponse * VtUrlDist_getResponse(struct VtUrlDist *vt_udist) {
  VtResponse_get(vt_udist->response);
  return vt_udist->response;
}

int VtUrlDist_getDistribution(struct VtUrlDist *vt_udist) {

  CURL *curl;
  CURLcode res;
  long http_response_code = 0;
  int ret = 0;
  char get_url[512];
  int len = 0;


  VtApiPage_resetBuffer((struct VtApiPage *) vt_udist);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  DBG(1, "Api Key =  '%s'\n", vt_udist->api_key);

  if (ret)
    VT_ERROR("Adding key\n");

  len = snprintf(get_url, sizeof(get_url)-1,  VT_API_BASE_URL "url/distribution?apikey=%s", vt_udist->api_key);
  if (len < 0) {
    VT_ERROR("sprintf\n");
    goto cleanup;
  }

  if (vt_udist->before) {
    len += ret = snprintf(get_url + len, strlen(get_url) - 1, "&before=%lld", vt_udist->before);
    if (ret < 0) {
      VT_ERROR("sprintf before\n");
      goto cleanup;
    }
  }

  if (vt_udist->after) {
    len += ret = snprintf(get_url + len, strlen(get_url) - 1, "&after=%lld", vt_udist->after);
    if (ret < 0) {
      VT_ERROR("sprintf after\n");
      goto cleanup;
    }
  }

  if (vt_udist->allinfo) {
    len += ret = snprintf(get_url + len, strlen(get_url) - 1, "&allinfo=true");
    if (ret < 0) {
      VT_ERROR("sprintf after\n");
      goto cleanup;
    }
  }

  if (vt_udist->limit) {
    len += ret = snprintf(get_url + len, strlen(get_url) - 1, "&limit=%d", vt_udist->limit);
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
    VT_ERROR("URL=%s\n", get_url);
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

int VtUrlDist_parse(struct VtUrlDist* url_dist,
                    void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
                    void *user_data) {
  json_t *resp_json, *url_obj;
  json_t *url_str_json, *timestamp_json, *total_json, *positives_json;
  unsigned int index;

  if (!url_dist || !url_dist->response) {
    VT_ERROR("No data recieved\n");
    return -1;
  }

  resp_json =  VtResponse_getJanssonObj(url_dist->response);

  if (!json_is_array(resp_json)) {
    VT_ERROR("JSON is not array\n");
    return -1;
  }

  json_array_foreach(resp_json, index, url_obj) {

    if (!json_is_object(url_obj)) {
      VT_ERROR("Parse error not a URL object\n");
      return -1;
    }

    url_str_json = json_object_get(url_obj, "url");
    if (!url_str_json || !json_is_string(url_str_json)) {
      VT_ERROR("Parse error: url string\n");
      return -1;
    }

    timestamp_json = json_object_get(url_obj, "timestamp");
    if (!timestamp_json || !json_is_integer(timestamp_json)) {
      VT_ERROR("JSON parse error timestamp\n");
      return -1;
    }

    total_json = json_object_get(url_obj, "total");
    if (!total_json || !json_is_integer(total_json)) {
      VT_ERROR("JSON parse error total\n");
      return -1;
    }

    positives_json = json_object_get(url_obj, "positives");
    if (!positives_json || !json_is_integer(positives_json)) {
      VT_ERROR("JSON parse error positives\n");
      return -1;
    }

    // set the after value, so if we do another query, we will not repeat the same data
    url_dist->after = json_integer_value(timestamp_json);

    // Call user defined callback function
    if (cb)
      cb(json_string_value(url_str_json), json_integer_value(timestamp_json),
         (int) json_integer_value(total_json), (int) json_integer_value(positives_json),
         url_obj, user_data);

  }

  return 0;
}

int VtUrlDist_process(struct VtUrlDist* url_dist,
                      void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
                      void *user_data) {
  int ret;

  ret = VtUrlDist_getDistribution(url_dist);
  if (ret) {
    return ret;
  }

  return  VtUrlDist_parse(url_dist, cb, user_data);
}

