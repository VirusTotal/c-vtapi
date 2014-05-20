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




struct VtIpAddr {
  API_OBJECT_COMMON;

};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtIpAddr_constructor(struct VtObject *obj) {
  struct VtIpAddr *vt_ip_addr = (struct VtIpAddr *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_ip_addr);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtIpAddr_destructor(struct VtObject *obj) {
  struct VtIpAddr *vt_ip_addr = (struct VtIpAddr *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_ip_addr);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtIpAddr",
  .obj_size           = sizeof(struct VtIpAddr),
  .obj_constructor    = VtIpAddr_constructor,
  .obj_destructor     = VtIpAddr_destructor,
};

static struct VtIpAddr* VtIpAddr_alloc(struct VtObject_ops *ops) {
  struct VtIpAddr *FileScan;

  FileScan = (struct VtIpAddr*) VtObject_alloc(ops);
  return FileScan;
}


struct VtIpAddr* VtIpAddr_new(void) {
  struct VtIpAddr *FileScan = VtIpAddr_alloc(&obj_ops);

  return FileScan;
}

/** Get a reference counter */
void VtIpAddr_get(struct VtIpAddr *obj) {
  VtObject_get((struct VtObject*) obj);
}

/** put a reference counter */
void VtIpAddr_put(struct VtIpAddr **obj) {
  VtApiPage_put((struct VtApiPage**) obj);
}

void VtIpAddr_setApiKey(struct VtIpAddr *vt_ip_addr, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)vt_ip_addr, api_key);
}


struct VtResponse * VtIpAddr_getResponse(struct VtIpAddr *vt_ip_addr) {
  VtResponse_get(vt_ip_addr->response);
  return vt_ip_addr->response;
}

int VtIpAddr_report(struct VtIpAddr *vt_ip_addr, const char *ip_addr_str) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  char get_url[512];
  int len = 0;

  VtApiPage_resetBuffer((struct VtApiPage *) vt_ip_addr);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  DBG(1, "Api Key =  '%s'\n", vt_ip_addr->api_key);

  if (ret)
    VT_ERROR("Adding key\n");

  len = snprintf(get_url, 511, VT_API_BASE_URL "ip-address/report?apikey=%s&ip=%s",
                vt_ip_addr->api_key, ip_addr_str);
  if (len < 0) {
    VT_ERROR("sprintf\n");
    goto cleanup;
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
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_ip_addr); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_ip_addr->buffer);

  // if a previous response
  if (vt_ip_addr->response)
    VtResponse_put(&vt_ip_addr->response);   // relase reference counter

  vt_ip_addr->response = VtResponse_new(); // new response object

  ret = VtResponse_fromJSONstr(vt_ip_addr->response, vt_ip_addr->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  return ret;
}

