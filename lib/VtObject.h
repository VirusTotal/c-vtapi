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

#ifndef VT_OBJECT_H
#define VT_OBJECT_H

#include <stdlib.h>
#include <stdbool.h>
#include <jansson.h>


#ifdef  __cplusplus
extern "C" {
#endif

#include "vtcapi_common.h"

/**
* @defgroup VtObject VtObject base object 
* @{
*/



/**
* Common VtObject Header
*
* This macro must be included as first member in every object,
* that inherits this object
* @var id    VtObject ID
* @var refcount  Counter for number of holders of this object
* @var mutex  for locking this object
*/
#ifdef WINDOWS
	#define VT_OBJECT_COMMON \
	int id; \
	int refcount; \
	CRITICAL_SECTION mutex;  \
	struct VtObject_ops *obj_ops

#define VT_OBJECT_LOCK(obj)  do { \
	DBG(3, "LOCKING obj %p\n", obj); \
	WaitForSingleObject(&((struct VtObject*)obj)->mutex, INFINTE); \
	DBG(3, "LOCKED %p\n", obj);  } while(0)

#define VT_OBJECT_UNLOCK(obj) do { \
	ReleaseMutex(&((struct VtObject*)obj)->mutex); \
	DBG(3, "UNLOCKED %p\n", obj); } while(0)

#else
	#define VT_OBJECT_COMMON \
	int id; \
	int refcount; \
	pthread_mutex_t mutex;  \
	struct VtObject_ops *obj_ops

#define VT_OBJECT_LOCK(obj)  do { \
	DBG(3, "LOCKING obj %p\n", obj); \
	pthread_mutex_lock(&((struct VtObject*)obj)->mutex); \
	DBG(3, "LOCKED %p\n", obj);  } while (0)

#define VT_OBJECT_UNLOCK(obj) do { \
	pthread_mutex_unlock(&((struct VtObject*)obj)->mutex); \
	DBG(3, "UNLOCKED %p\n", obj);\
	} while (0)

#endif




// flags for toJSON()  functions





struct VtObject_ops;

/**
* @struct VtObject
* @brief This is a base object that all other object will inherit
* it features a unique ID per object and reference counters
*/
struct VtObject
{
	/** Base class members */
	VT_OBJECT_COMMON;
};


/**
* @struct VtObject_ops
* @brief VtObject operations, defines various VtObject properties and callbacks.
*/
struct VtObject_ops
{
	/** Unique type name of the object */
	char * obj_type;

	/** Size of object */
	size_t obj_size;

	/**
	* Optional callback to init/allocate any private data
	*/
	int (*obj_constructor)(struct VtObject *);

	/**
	* Optional callback to free any private data
	*/
	int (*obj_destructor)(struct VtObject *);

	/*optional callback to clone private data */
	int (*obj_clone)(struct VtObject *dst, struct VtObject *src);
	
	/** optional callback to compare two objects
	 @return 0 if equal. -1, 1 see man qsort()
	*/
	int (*obj_compare)(const struct VtObject *dst,const struct VtObject *src);


	/** optional callback to create from JSON
	 @return 0 if equal. -1, 1 see man qsort()
	*/
	int (*obj_from_json)(struct VtObject *, json_t *src);

	json_t * (*obj_to_json)(struct VtObject *, int flags);

	char * (*obj_to_json_str)(struct VtObject *);

};


void VtObject_register(struct VtObject_ops *ops);

struct VtObject *VtObject_alloc(struct VtObject_ops *ops);

void VtObject_free(struct VtObject **obj);

/**
* @name Reference Management
* @{
*/

/**
* Release a reference from an object.
* When reference count reaches 0 free and will NULL pointer
* @arg obj	object to release reference from
*/
void VtObject_put(struct VtObject **obj);

/**
* Acquire a reference on a object
* @arg obj  	object to acquire reference from
*/
void VtObject_get(struct VtObject *obj);

/**
* Check whether this object is used by multiple users
* @arg obj		object to check
* @return true or false
*/
bool VtObject_shared(struct VtObject *obj);

/** @}
end of refrence management
*/

struct VtObject* VtObject_newByName(const char *name);

struct VtObject* VtObject_newFromJSON(json_t *json);


json_t * VtObject_toJSON(struct VtObject *obj, int flags);

/**
 * @brief convert object to json string
 *
 * @param obj ...
 * @return char*  caller must free
 **/
char * VtObject_toJSONstr(struct VtObject *obj);


/** @}  */

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif

