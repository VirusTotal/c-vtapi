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

struct VtDomain {
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
int VtDomain_constructor(struct VtObject *obj) {
  struct VtDomain *vt_domain = (struct VtDomain *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_domain);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtDomain_destructor(struct VtObject *obj) {
  struct VtDomain *vt_domain = (struct VtDomain *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_domain);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtDomain",
  .obj_size           = sizeof(struct VtDomain),
  .obj_constructor    = VtDomain_constructor,
  .obj_destructor     = VtDomain_destructor,
};

static struct VtDomain* VtDomain_alloc(struct VtObject_ops *ops) {
  struct VtDomain *vt_domain;

  vt_domain = (struct VtDomain*) VtObject_alloc(ops);
  return vt_domain;
}


struct VtDomain* VtDomain_new(void) {
  struct VtDomain *vt_domain = VtDomain_alloc(&obj_ops);

  return vt_domain;
}

/** Get a reference counter */
void VtDomain_get(struct VtDomain *obj) {
  VtObject_get((struct VtObject*) obj);
}

/** put a reference counter */
void VtDomain_put(struct VtDomain **obj) {
  VtApiPage_put((struct VtApiPage**) obj);
}

void VtDomain_setApiKey(struct VtDomain *vt_domain, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)vt_domain, api_key);
}


struct VtResponse * VtDomain_getResponse(struct VtDomain *vt_domain) {

  if (vt_domain->response) {
    VtResponse_get(vt_domain->response);
    return vt_domain->response;
  }

  return NULL;
}

int VtDomain_report(struct VtDomain *vt_domain, const char *ip_addr_str) {

  CURL *curl;
  CURLcode res;
  int ret = 0;
  char get_url[512];
  int len = 0;


  VtApiPage_resetBuffer((struct VtApiPage *) vt_domain);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  DBG(1, "Api Key =  '%s'\n", vt_domain->api_key);

  if (ret)
    VT_ERROR("Adding key\n");

  len = sprintf(get_url, VT_API_BASE_URL "domain/report?apikey=%s&domain=%s",
                vt_domain->api_key, ip_addr_str);
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
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_domain); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for VT_ERRORs */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_domain->buffer);

  // if a previous response
  if (vt_domain->response)
    VtResponse_put(&vt_domain->response);   // relase reference counter

  vt_domain->response = VtResponse_new(); // new response object

  ret = VtResponse_fromJSONstr(vt_domain->response, vt_domain->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  return ret;
}

