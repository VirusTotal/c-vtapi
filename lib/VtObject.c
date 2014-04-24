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

#if !defined(_WIN32) && !defined(_WIN64)
#include <pthread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#ifdef HAVE_CONFIG_H
#include "c-vtapi_config.h"
#endif

#include "VtObject.h"

#include "vtcapi_common.h"

/**
@mainpage C API for VirusTotal
@author Karl Hiramoto <karl.hiramoto@virustotal.com>
@date 2014

@section Intro Introduction

This is a library to implement API calls for VirusTotal's http://www.virustotal.com/
public and private API's.

The public API is available to anyone who registers at www.virustotal.com.
The private API features are only available to users with a private API licence.

@section ReferenceCounting  Reference Counting
Objects in this library use reference counters to track their use.
Newly created objects have a count of one.  Use the ObjectName_get() function to get another reference.
Use ObjectName_put() to release the reference.
When the counter to the reference reaches zero the object is freed with free()

@section CodingStyle Coding Style
If you want to send patches to this libary please follow the google coding style
@see http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml


@section ObjectOriented   Object Oriented Coding sytle.
This library is using pure C in an object oriented way.

All object inherit VtObject base object.
If you are just a user of this library and not developing the library don't worry about this.


*/




/// VtObject ID sequence.  NOTE  object allocation for now only done by one thread so no mutex needed yet.
static unsigned int id_seq = 0;

#ifdef WINDOWS
CRITICAL_SECTION mutex;
#else
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static unsigned int num_obj_types = 0;
struct VtObject_ops **obj_types_list = NULL;


void VtObject_register(struct VtObject_ops *ops) {
  LOCK_MUTEX(&mutex);
  obj_types_list = realloc(obj_types_list, sizeof(struct VtObject_ops*) *(num_obj_types+2));
  if (unlikely(obj_types_list == NULL)) {
    VT_ERROR("no memory to allocate object list\n");
  } else {
    obj_types_list[num_obj_types] = ops;
    num_obj_types++;
  }
  UNLOCK_MUTEX(&mutex);
  DBG(1, "registered '%s'\n", ops->obj_type);
}


static struct VtObject_ops *get_obj_ops(struct VtObject *obj) {
  if (!obj->obj_ops)
    BUG();

  return obj->obj_ops;
}


/**
* Allocate a new object of kind specified by the operations handle
* @arg ops		operations handle
* @return The new object or NULL
*/
struct VtObject *VtObject_alloc(struct VtObject_ops *ops) {
  struct VtObject *new_obj;
  int retval = 0;
  if (ops->obj_size < sizeof(struct VtObject))
    BUG();

  new_obj = calloc(1, ops->obj_size);
  if (!new_obj)
    return NULL;

  new_obj->id = id_seq++;

  new_obj->refcount = 1;

  new_obj->obj_ops = ops;
  if (ops->obj_constructor) {
    retval = ops->obj_constructor(new_obj);
    if (retval) {
      VT_ERROR("Allocating object, constructor failed");
      free(new_obj);
      return NULL;
    }
  }
  DBG(DGB_LEVEL_MEM, "Allocated new object %p name='%s' size=%zd\n", new_obj, ops->obj_type, ops->obj_size);

  return new_obj;
}

/**
* free an object
* @brief call object destructor.
* @brief Note this should only be called from VtObject_put() or an inherited _put()
* @arg obj  pointer to pointer to object so we can return NULL pointer of free'd memory
*/
void VtObject_free(struct VtObject **obj) {
  struct VtObject_ops *ops = get_obj_ops(*obj);

  if ((*obj)->refcount > 0)
    DBG(1, "Warning: Freeing object in use... name='%s'\n", ops->obj_type);

  if (ops->obj_destructor)
    ops->obj_destructor(*obj);

  DBG(DGB_LEVEL_MEM, "Free object %p name='%s'\n", *obj, ops->obj_type);

  free(*obj);
  *obj = NULL;
}

/**
* @name Reference Management
* @{
*/

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void VtObject_get(struct VtObject *obj) {
  obj->refcount++;
  DBG(DGB_LEVEL_MEM, "New reference to object %p, total refcount %d\n",
      obj, obj->refcount);
}

/**
* Release a reference from an object
* @arg obj		object to release reference from
*/
void VtObject_put(struct VtObject **obj_arg) {
  struct VtObject *obj;
  if (!*obj_arg)
    return;

  obj = *obj_arg; // derefernce only once

  obj->refcount--;
  DBG(DGB_LEVEL_MEM, "Returned object reference %p, %d remaining type: %s\n",
      obj, obj->refcount,  obj->obj_ops->obj_type);

  if (obj->refcount < 0) {
    VT_ERROR_FATAL("Refcount = %d \n", obj->refcount);
  }

  if (obj->refcount <= 0)
    VtObject_free(obj_arg);

  *obj_arg = NULL;
}
/**  @}   */


/**
* Check whether this object is used by multiple users
* @arg obj		object to check
* @return true or false
*/
bool VtObject_shared(struct VtObject *obj) {
  return obj->refcount > 1;
}

/*
struct VtObject* VtObject_newByName(const char *name)
{
	int i;
	struct VtObject_ops *ops;
	struct VtObject  *obj = NULL;

	pthread_mutex_lock(&mutex);
	for (i = 0; i < num_obj_types; i++) {
		ops = obj_types_list[i];
		if (ops && ops->obj_type && !strcmp(ops->obj_type, name)) {
			obj = (struct VtObject*) VtObject_alloc(ops);
			break;
		}
	}

	pthread_mutex_unlock(&mutex);

	return obj;
}


struct VtObject* VtObject_newFromJSON(json_t *json_obj)
{
	struct VtObject* obj;
	void *iter;
	const char *key = NULL;
	struct VtObject_ops *ops = NULL;
	int ret = 0;

	if (!json_obj) {
		VT_ERROR("json_obj is null \n");
		return NULL;
	}

	iter = json_object_iter(json_obj);
	if (!iter) {
		VT_ERROR("unable to iterate json object\n");
		return NULL;
	}

	key = json_object_iter_key(iter);
	DBG(1, "json key '%s'\n", key);

	// allocate object and call constructor
	obj = VtObject_newByName(key);
	if (!obj) {
		VT_ERROR("Unable to allocate object of type '%s'\n", key);
		return NULL;
	}
	ops = get_obj_ops(obj);

	if (ops->obj_from_json) {
		ret = ops->obj_from_json(obj, json_object_iter_value(iter));
		if (ret) {
			VT_ERROR("Parsing JSON\n");
		}
	} else {
		WARN("No fromJSON callback on object type '%s'\n", key);
	}

	return obj;
}
*/

json_t * VtObject_toJSON(struct VtObject *obj, int flags) {
  struct VtObject_ops *ops = NULL;

  ops = get_obj_ops(obj);
  if (!ops) {
    VT_ERROR("NO object ops");
    return NULL;
  }

  if (!ops->obj_to_json) {
    WARN("No toJSON callback on object type '%s'\n", ops->obj_type);
    return  NULL;
  }

  return ops->obj_to_json(obj, flags);
}

char * VtObject_toJSONstr(struct VtObject *obj) {
  struct VtObject_ops *ops = NULL;

  ops = get_obj_ops(obj);
  if (!ops) {
    VT_ERROR("NO object ops");
    return NULL;
  }

  if (!ops->obj_to_json_str) {
    WARN("No toJSONstr callback on object type '%s'\n", ops->obj_type);
    return  NULL;
  }



  return ops->obj_to_json_str(obj);
}

static void CCALL VtObject_exit(void) {
  if (obj_types_list)
    free(obj_types_list);
}



INITIALIZER(VtObject_init) {
  char *level = NULL;
  DBG(1, "init object\n");

#ifdef WINDOWS
  InitializeCriticalSection(&mutex);
#endif

  num_obj_types = 0;
  obj_types_list = NULL;

  level = getenv("VT_DEBUG");
  if (level) {
    debug_level = atoi(level);
  }

  curl_global_init(CURL_GLOBAL_ALL);
  atexit(VtObject_exit);
}
