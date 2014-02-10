#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "vtcapi-config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <curl/curl.h>


#include "VtObject.h"
#include "VtApiPage.h"
#include "VtResponse.h"

#include "vtcapi_common.h"



struct VtFileScan
{
	API_OBJECT_COMMON
	char *offset;
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtFileScan_constructor(struct VtObject *obj)
{
	struct VtFileScan *file_scan = (struct VtFileScan *)obj;

	DBG(DGB_LEVEL_MEM, " constructor %p\n", file_scan);

	return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtFileScan_destructor(struct VtObject *obj)
{
	struct VtFileScan *file_scan = (struct VtFileScan *)obj;

	DBG(DGB_LEVEL_MEM, " destructor %p\n", file_scan);

	if (file_scan->offset)
		free(file_scan->offset);

	// Parent destructor
	return VtApiPage_destructor((struct VtObject *)obj);	
}



/** @} */


static struct VtObject_ops obj_ops = {
	.obj_type           = "file/scan",
	.obj_size           = sizeof(struct VtFileScan),
	.obj_constructor    = VtFileScan_constructor,
	.obj_destructor     = VtFileScan_destructor,
};

static struct VtFileScan* VtFileScan_alloc(struct VtObject_ops *ops)
{
	struct VtFileScan *FileScan;

	FileScan = (struct VtFileScan*) VtObject_alloc(ops);
	return FileScan;
}


struct VtFileScan* VtFileScan_new(void)
{
	struct VtFileScan *FileScan = VtFileScan_alloc(&obj_ops);

	return FileScan;
}

/** Get a reference counter */
void VtFileScan_get(struct VtFileScan *FileScan)
{
	VtObject_get((struct VtObject*) FileScan);
}

/** put a reference counter */
void VtFileScan_put(struct VtFileScan **FileScan)
{
	VtApiPage_put((struct VtApiPage**) FileScan);
}



void VtFileScan_setApiKey(struct VtFileScan *file_scan, const char *api_key)
{
	// Call parent function
	return VtApiPage_setApiKey((struct VtApiPage *)file_scan, api_key);
}


void VtFileScan_setOffset(struct VtFileScan *file_scan, const char *offset)
{
	if (file_scan->offset) {
		free(file_scan->offset);
	}
	if (offset)
		file_scan->offset = strdup(offset);
	else
		file_scan->offset = NULL;
}


struct VtResponse * VtFileScan_getResponse(struct VtFileScan *file_scan)
{
	VtResponse_get(file_scan->response);
	return file_scan->response;
}

int VtFileScan_scan(struct VtFileScan *file_scan, const char *file_path)
{

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
		ERROR("init curl\n");
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
		ERROR("Adding file %s\n", file_path);
	
	/* Fill in the filename field */ 
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "filename",
			  CURLFORM_COPYCONTENTS, file_path, // FIXME
			  CURLFORM_END);
	if (ret)
		ERROR("Adding filename %s\n", file_path);
	
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "apikey",
			  CURLFORM_COPYCONTENTS, file_scan->api_key,
			  CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/scan");

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg


	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);

	if (file_scan->response)
		VtResponse_put(&file_scan->response);

	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
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


int VtFileScan_rescanHash(struct VtFileScan *file_scan,
 const char *hash,
	time_t rescan_date, int period, int repeat,
	const char *notify_url, bool notify_changes_only)
{
	
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
		ERROR("init curl\n");
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
		ERROR("Adding hash %s\n", hash);

	if (rescan_date) {
		if (!gmtime_r(&rescan_date, &time_result)) {
			ERROR("Converting time\n");
			goto cleanup;
		}

		ret = strftime(buff, sizeof(buff)-1, "%Y%m%d%H%M%S", &time_result);
		ret = curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "date",
				CURLFORM_COPYCONTENTS,  buff,
				CURLFORM_END);
		if (ret)
			ERROR("Adding date %s\n", buff);
	}

	if (period) {
		sprintf(buff, "%d", period);
		ret = curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "period",
				CURLFORM_COPYCONTENTS,  buff,
				CURLFORM_END);
		if (ret)
			ERROR("Adding period %s\n", buff);
	}

	if (repeat) {
		sprintf(buff, "%d", repeat);
		ret = curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "repeat",
				CURLFORM_COPYCONTENTS,  buff,
				CURLFORM_END);
		if (ret)
			ERROR("Adding repeat %s\n", buff);
	}

	if (notify_url) {
		ret = curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "notify_url",
				CURLFORM_COPYCONTENTS,  notify_url,
				CURLFORM_END);
		if (ret)
			ERROR("Adding notify_url %s\n", notify_url);

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
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/rescan");
	
#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form
	
	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg


	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);
	if (file_scan->response)
		VtResponse_put(&file_scan->response);

	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
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

int VtFileScan_rescanDelete(struct VtFileScan *file_scan,
 const char *hash)
{
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
		ERROR("init curl\n");
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
		ERROR("Adding hash %s\n", hash);

	ret = curl_formadd(&formpost,
					   &lastptr,
					   CURLFORM_COPYNAME, "apikey",
					   CURLFORM_COPYCONTENTS, file_scan->api_key,
					   CURLFORM_END);

	if (ret)
		ERROR("Adding key\n");

	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/rescan/delete");

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg


	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);
	if (file_scan->response)
		VtResponse_put(&file_scan->response);

	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
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


int VtFileScan_report(struct VtFileScan *file_scan, const char *hash)
{
	
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
		ERROR("init curl\n");
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
		ERROR("Adding hash %s\n", hash);

	ret = curl_formadd(&formpost,
					   &lastptr,
					   CURLFORM_COPYNAME, "apikey",
					   CURLFORM_COPYCONTENTS, file_scan->api_key,
					   CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/report");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg

	
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	} else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
		if (http_response_code != 200) {
			ERROR("HTTP Response code: %ld\n", http_response_code);
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
		ERROR("Parsing JSON\n");
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


int VtFileScan_search(struct VtFileScan *file_scan, const char *query,
	void (*cb)(const char *resource, void *data),
	void *user_data)
{
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
		ERROR("search query can not be empty\n");
		return -1;
	}

	VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
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
		ERROR("Adding qury %s\n", query);

	ret = curl_formadd(&formpost,
					   &lastptr,
					   CURLFORM_COPYNAME, "apikey",
					   CURLFORM_COPYCONTENTS, file_scan->api_key,
					   CURLFORM_END);
	if (ret)
		ERROR("Adding key\n");



	if (file_scan->offset) {
		ret = curl_formadd(&formpost,
			&lastptr,
			CURLFORM_COPYNAME, "offset",
			CURLFORM_COPYCONTENTS, file_scan->offset,
			CURLFORM_END);
		if (ret)
			ERROR("Adding offset\n");

	}

// 	DBG(1, "URL=%s \n", url);
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/search");

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	} else {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
		if (http_response_code != 200) {
			ERROR("HTTP Response code: %ld\n", http_response_code);
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
		ERROR("Parsing JSON\n");
		goto cleanup;
	}
	resp_json =  VtResponse_getJanssonObj(file_scan->response);

	if (resp_json) {
		json_t *offset_json = json_object_get(resp_json, "offset");
		if (json_is_string(offset_json))
		{
			VtFileScan_setOffset(file_scan, json_string_value(offset_json));
		}
	}

	if (cb && resp_json) {
		json_t *hashes_json = json_object_get(resp_json, "hashes");
		int index;
		json_t *hash_obj;
		json_t *offset_json = json_object_get(resp_json, "offset");

		if (offset_json && json_is_string(offset_json)
			&& json_string_value(offset_json) && json_string_value(offset_json)[0]) {
			VtFileScan_setOffset(file_scan, json_string_value(offset_json));
		}

		if (!hashes_json || !json_is_array(hashes_json)) {
			ERROR("Parse error: hashes\n");
			goto cleanup;
		}

		json_array_foreach(hashes_json, index, hash_obj) {
			if (!json_is_string(hash_obj)) {
				ERROR("hash is not string\n");
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



int VtFileScan_uploadUrl(struct VtFileScan *file_scan, char **url)
{
	CURL *curl;
	CURLcode res;
	int ret = 0;
	json_t *resp_json = NULL;
	char get_url[768];

	VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}

	ret = snprintf(get_url, sizeof(get_url)-1,
		VT_API_BASE_URL "file/scan/upload_url?apikey=%s",
		file_scan->api_key);

	curl_easy_setopt(curl, CURLOPT_URL, get_url);

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg


	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	} else  {

	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);

	if (file_scan->response)
		VtResponse_put(&file_scan->response);
	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
		goto cleanup;
	}
	resp_json =  VtResponse_getJanssonObj(file_scan->response);

	if (resp_json) {
		json_t *url_json = json_object_get(resp_json, "upload_url");
		if (json_is_string(url_json))
		{
			*url = strdup(json_string_value(url_json));
		}
	}

cleanup:

	/* always cleanup */
	curl_easy_cleanup(curl);

	return ret;
}


