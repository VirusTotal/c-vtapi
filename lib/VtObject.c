#include <pthread.h>
#include <stdlib.h>
#include <string.h>


/*
#ifdef HAVE_CONFIG_H
#include "vtcapi-config.h"
#endif*/

#include "VtObject.h"

#include "vtcapi_common.h"



/// VtObject ID sequence.  NOTE  object allocation for now only done by one thread so no mutex needed yet. 
static unsigned int id_seq = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


static unsigned int num_obj_types = 0;
struct VtObject_ops **obj_types_list = NULL;

static void __init__(105) __VtObject_init(void)
{
	DBG(1, "init object\n");
	num_obj_types = 0;
	obj_types_list = NULL;
}

void VtObject_register(struct VtObject_ops *ops)
{
	pthread_mutex_lock(&mutex);
	obj_types_list = realloc(obj_types_list, sizeof(struct VtObject_ops*) *(num_obj_types+2));
	if (unlikely(obj_types_list == NULL)) {
		ERROR("no memory to allocate object list\n");
	} else {
		obj_types_list[num_obj_types] = ops;
		num_obj_types++;
	}
	pthread_mutex_unlock(&mutex);
	DBG(1, "registered '%s'\n", ops->obj_type);
}


static struct VtObject_ops *get_obj_ops(struct VtObject *obj)
{
	if (!obj->obj_ops)
		BUG();

	return obj->obj_ops;
}


/**
* Allocate a new object of kind specified by the operations handle
* @arg ops		operations handle
* @return The new object or NULL
*/
struct VtObject *VtObject_alloc(struct VtObject_ops *ops)
{
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
			ERROR("Allocating object, constructor failed");
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
void VtObject_free(struct VtObject **obj)
{
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
void VtObject_get(struct VtObject *obj)
{
	obj->refcount++;
	DBG(DGB_LEVEL_MEM, "New reference to object %p, total refcount %d\n",
		obj, obj->refcount);
}

/**
* Release a reference from an object
* @arg obj		object to release reference from
*/
void VtObject_put(struct VtObject **obj_arg)
{
	struct VtObject *obj;
	if (!*obj_arg)
		return;

	obj = *obj_arg; // derefernce only once

	obj->refcount--;
	DBG(DGB_LEVEL_MEM, "Returned object reference %p, %d remaining type: %s\n",
		obj, obj->refcount,  obj->obj_ops->obj_type);

	if (obj->refcount < 0) {
		ERROR_FATAL("Refcount = %d \n", obj->refcount);
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
bool VtObject_shared(struct VtObject *obj)
{
	return obj->refcount > 1;
}

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
		ERROR("json_obj is null \n");
		return NULL;
	}

	iter = json_object_iter(json_obj);
	if (!iter) {
		ERROR("unable to iterate json object\n");
		return NULL;
	}

	key = json_object_iter_key(iter);
	DBG(1, "json key '%s'\n", key);
	
	// allocate object and call constructor
	obj = VtObject_newByName(key);
	if (!obj) {
		ERROR("Unable to allocate object of type '%s'\n", key);
		return NULL;
	}
	ops = get_obj_ops(obj);

	if (ops->obj_from_json) {
		ret = ops->obj_from_json(obj, json_object_iter_value(iter));
		if (ret) {
			ERROR("Parsing JSON\n");
		}
	} else {
		WARN("No fromJSON callback on object type '%s'\n", key);
	}
	
	return obj;
}

json_t * VtObject_toJSON(struct VtObject *obj, int flags)
{
	struct VtObject_ops *ops = NULL;

	ops = get_obj_ops(obj);
	if (!ops) {
		ERROR("NO object ops");
		return NULL;
	}

	if (!ops->obj_to_json) {
		WARN("No toJSON callback on object type '%s'\n", ops->obj_type);
		return  NULL;
	}
	
	return ops->obj_to_json(obj, flags);
}

char * VtObject_toJSONstr(struct VtObject *obj)
{
	struct VtObject_ops *ops = NULL;

	ops = get_obj_ops(obj);
	if (!ops) {
		ERROR("NO object ops");
		return NULL;
	}

	if (!ops->obj_to_json_str) {
		WARN("No toJSONstr callback on object type '%s'\n", ops->obj_type);
		return  NULL;
	}
	
	return ops->obj_to_json_str(obj);
}

static void __exit__(105) VtObject_exit(void)
{
	if (obj_types_list)
		free(obj_types_list);
}
