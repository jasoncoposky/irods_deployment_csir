# iRODS Logical Quotas Policy
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# This rulebase allows an administrator to apply a maximum limit to the number of data
# objects and bytes a collection can hold. Changes within tracked sub-collections are captured
# as well. Tracked collections can be nested and changes are propagated up the tree.
#
# This script handles the put, rename, copy, and remove operations.
#
#                                  *** IMPORTANT ***
#
# Due to the asynchronous nature of iRODS and the lack of atomic operations in the rule
# language, this implementation is likely to never be consistent. Instead, it is more so
# meant to provide some idea as to what the current state of the zone looks like. Using
# a background process to keep things in sync could remedy this issue.
#
# ------
#
# Getting Started:
#
# To enable logical quotas, you first need to be running the Native Rule Engine Plugin.
# If you have that, all you need to do is run the following command:
#
#   irule -r <native_rule_language_instance> 'logical_quotas_init(<collection>, <maximum_object_count>, <maximum_data_size_in_bytes>)' null null
#
# If everything worked, you should have new metadata AVUs attached to <collection> with
# the following names:
#
#   - irods::logical_quotas::maximum_object_count
#   - irods::logical_quotas::maximum_data_size_in_bytes
#   - irods::logical_quotas::current_object_count
#   - irods::logical_quotas::current_data_size_in_bytes
#

#
# Configuration
#

# Defines the namespace for logical quotas metadata attribute names.
# Feel free to adjust this value if necessary.
logical_quotas_namespace { "irods::logical_quotas"; }

# Returns *name prefixed with the string returned by logical_quotas_namespace().
#
# Parameters:
# - *name: The string to prefix.
logical_quotas_key(*name)
{
    logical_quotas_namespace() ++ "::*name";
}

# Constants used for tracking object counts and data sizes.
# Feel free to adjust these if necessary.
logical_quotas_maximum_object_count_key       { logical_quotas_key("maximum_object_count"); }
logical_quotas_maximum_data_size_in_bytes_key { logical_quotas_key("maximum_data_size_in_bytes"); }
logical_quotas_current_object_count_key       { logical_quotas_key("current_object_count"); }
logical_quotas_current_data_size_in_bytes_key { logical_quotas_key("current_data_size_in_bytes"); }

# The default error code returned when a logical quota is exceeded.
SYS_INVALID_INPUT_PARAM { -130000; }

# Returns an error code and error message to the REPF if *ec is less than 0.
#
# Parameters:
# - *ec: The error code to return to the REPF.
# - *msg: The error message string to return to the REPF.
logical_quotas_fail_if_error(*ec, *msg)
{
    if (*ec < 0) {
        failmsg(*ec, *msg);
    }
}

#
# The following error handlers are for convenience.
#

logical_quotas_fail_if_split_path_error(*ec, *path)
{
    logical_quotas_fail_if_error(*ec, "Could not split path into parent and child [*path]");
}

logical_quotas_fail_if_set_key_value_pairs_error(*ec, *path)
{
    logical_quotas_fail_if_error(*ec, "Could not update logical quotas totals for path [*path]");
}

logical_quotas_fail_if_object_type_error(*ec, *path)
{
    logical_quotas_fail_if_error(*ec, "Could not get the object type [*path]");
}

logical_quotas_invalid_object_type_error(*path, *obj_type)
{
    *INVALID_OBJECT_TYPE = -1105000;
    failmsg(*INVALID_OBJECT_TYPE, "Object is not a collection or data object [path => *path, type => *obj_type]");
}

get_collection_id(*coll_path) {
    *id = 0;
    foreach(*row in SELECT COLL_ID WHERE COLL_NAME = '*coll_path') {
        *id = *row.COLL_ID
    }

    *id
} # get_collection_id

get_collection_owner_user_id(*coll_id) {
    *user_id = 0
    foreach(*row in SELECT COLL_ACCESS_USER_ID WHERE COLL_ACCESS_COLL_ID = '*coll_id' and COLL_ACCESS_NAME = 'own') {
        *user_id = *row.COLL_ACCESS_USER_ID
    }
    *user_id
} # get_collection_owner_user_id

collection_owner_user_name(*coll_path) {
    *coll_id = get_collection_id(*coll_path)
    *user_id = get_collection_owner_user_id(*coll_id)
    *user_name = ""
    foreach(*row in SELECT USER_NAME WHERE USER_ID = '*user_id') {
        *user_name = *row.USER_NAME
    }

    *user_name
}

# Adds metadata to a collection that helps to enforce an upper limit
# on the number of objects (collections and data objects) and size (in bytes)
# a particular collection can hold.
#
# Parameters:
# - *coll_path: The collection that tracks the number of objects and size.
# - *max_number_of_objects: The total number of objects the collection is allowed to hold.
# - *max_size_in_bytes: The total number of bytes the collection is allowed to hold.
logical_quotas_init(*coll_path, *max_number_of_objects, *max_size_in_bytes)
{
    *owner_name = collection_owner_user_name(*coll_path)
    msiproxy_user(*owner_name, *prev_user_name)

    *count = 0;
    *size = 0;
    foreach (*row in select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = "*coll_path" || like "*coll_path/%") {
        *count = int(*row.DATA_NAME);
        *size = int(*row.DATA_SIZE);
    }

    *mcount = logical_quotas_maximum_object_count_key();
    *msize = logical_quotas_maximum_data_size_in_bytes_key();
    *ccount = logical_quotas_current_object_count_key();
    *csize = logical_quotas_current_data_size_in_bytes_key();

    *kvp.*mcount = "*max_number_of_objects";
    *kvp.*msize = "*max_size_in_bytes";
    *kvp.*ccount = "*count";
    *kvp.*csize = "*size";

    *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *coll_path, "-C"), *msg);

    msiproxy_user(*prev_user_name, *dontcare)

    logical_quotas_fail_if_error(*ec, "Could not initialize logical quotas policy for path [" ++ *coll_path ++ "]");
}

# Returns the parent path of *path. If *path is empty or points to the root
# collection, an empty string is returned.
#
# Parameters:
# - *path: The canonical path of a collection or data object.
logical_quotas_get_parent_collection(*path)
{
    *parent = "";

    if (*path != "" && *path != "/") {
        *ec = errormsg(msiSplitPath(*path, *parent, *_), *msg);
        logical_quotas_fail_if_split_path_error(*ec, *path);
    }

    *parent;
}

# Returns the first ancestor path that has been initialized via logical_quotas_init, else the
# empty string.
#
# Parameters:
# - *path: The canonical path of a collection or data object.
logical_quotas_get_tracked_parent_collection(*path)
{
    *p = *path;
    *tracked_path = "";

    while (*p != "") {
        if (logical_quotas_is_tracking(*p)) {
            *tracked_path = *p;
            break;
        }

        *p = logical_quotas_get_parent_collection(*p);
    }

    *tracked_path;
}

# Returns true if *parent_path is a prefix of *child_path.
#
# Parameters:
# - *parent_path: The prefix path.
# - *child_path: The path to which *parent_path is a prefix of.
logical_quotas_is_parent_path(*parent_path, *child_path)
{
    "*child_path" like "*parent_path/.+"
}

# Computes the total number of objects and the total bytes under *coll_path.
#
# Parameters:
# - *coll_path: The canonical path of a collection.
# - *count: Will hold the total number of objects under *coll_path.
# - *size: Will hold the total bytes under *coll_path.
logical_quotas_compute_object_count_and_size(*coll_path, *count, *size)
{
    *count = 0;
    *size = 0;

    foreach (*row in select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = "*coll_path" || like "*coll_path/%") {
        *count = int(*row.DATA_NAME);
        *size = int(*row.DATA_SIZE);
    }
}

# Returns true if *coll_path has been initialized via logical_quotas_init, else false.
#
# Parameters:
# - *coll_path: The collection to check.
logical_quotas_is_tracking(*coll_path)
{
    *is_tracking = false;
    *key = logical_quotas_maximum_object_count_key();

    foreach (*row in select META_COLL_ATTR_NAME where COLL_NAME = "*coll_path" and META_COLL_ATTR_NAME = "*key") {
        *is_tracking = true;
    }

    *is_tracking;
}

# Returns true if *path points to a valid data object, else false.
#
# Parameters:
# - *path: The canonical path to a data object.
logical_quotas_data_object_exists(*path)
{
    *ec = errormsg(msiSplitPath(*path, *coll_name, *data_name), *msg);
    logical_quotas_fail_if_split_path_error(*ec, *path);

    *found = false;

    foreach (*row in select DATA_NAME where COLL_NAME = "*coll_name" and DATA_NAME = "*data_name") {
        *found = true;
    }

    *found;
}

# Returns a key-value pair containing the information for tracking and enforcing the policy.
# Calling this rule on a path that has not been initialized via logical_quotas_init will produce an error.
#
# Parameters:
# - *coll_path: The path to a collection that was initialized via logical_quotas_init.
logical_quotas_get_tracking_info(*coll_path)
{
    *mcount = logical_quotas_maximum_object_count_key();
    *msize = logical_quotas_maximum_data_size_in_bytes_key();
    *ccount = logical_quotas_current_object_count_key();
    *csize = logical_quotas_current_data_size_in_bytes_key();

    foreach (*row in select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = "*coll_path") {
        if (*row.META_COLL_ATTR_NAME == *mcount) {
            *kvp.*mcount = *row.META_COLL_ATTR_VALUE;
        }
        else if (*row.META_COLL_ATTR_NAME == *msize) {
            *kvp.*msize = *row.META_COLL_ATTR_VALUE;
        }
        else if (*row.META_COLL_ATTR_NAME == *ccount) {
            *kvp.*ccount = *row.META_COLL_ATTR_VALUE;
        }
        else if (*row.META_COLL_ATTR_NAME == *csize) {
            *kvp.*csize = *row.META_COLL_ATTR_VALUE;
        }
    }

    *kvp;
}

# Returns the size of the data object at *path, else 0.
#
# Parameters:
# - *path: The canonical path to a valid data object.
logical_quotas_get_data_object_size(*path)
{
    *ec = errormsg(msiSplitPath(*path, *coll_name, *data_name), *msg);
    logical_quotas_fail_if_split_path_error(*ec, *path);

    *data_size = 0;

    foreach (*row in select DATA_SIZE where COLL_NAME = "*coll_name" and DATA_NAME = "*data_name") {
        *data_size = int(*row.DATA_SIZE);
    }

    *data_size;
}

# Terminates and produces an error if the max number of objects is exceeded after
# adding *delta to the current number of objects in *kvp.
#
# Parameters:
# - *kvp: A key-value pair created by logical_quotas_init.
# - *delta: The potential increase in the number of objects.
logical_quotas_fail_if_max_count_violation(*kvp, *delta)
{
    *mcount = logical_quotas_maximum_object_count_key();
    *ccount = logical_quotas_current_object_count_key();

    if (int(*kvp.*ccount) + abs(*delta) > int(*kvp.*mcount)) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Policy Violation: Adding object exceeds max number of objects limit");
    }
}

# Terminates and produces an error if the max number of bytes is exceeded after
# adding *delta to the current number of bytes in *kvp.
#
# Parameters:
# - *kvp: A key-value pair created by logical_quotas_init.
# - *delta: The potential increase in the number of bytes.
logical_quotas_fail_if_max_size_violation(*kvp, *delta)
{
    *msize = logical_quotas_maximum_data_size_in_bytes_key();
    *csize = logical_quotas_current_data_size_in_bytes_key();

    if (int(*kvp.*csize) + abs(*delta) > int(*kvp.*msize)) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Policy Violation: Adding objects exceeds max number of bytes limit");
    }
}

# Adjusts the current number of objects and bytes in *kvp by *num_objects and *size_in_bytes.
#
# Parameters:
# - *kvp: The key-value pair created by logical_quotas_init.
# - *num_objects: The amount to apply to the current number of objects in *kvp.
# - *size_in_bytes: The amount to apply to the current size in *kvp.
logical_quotas_add_objects_and_size(*kvp, *num_objects, *size_in_bytes)
{
    *ccount = logical_quotas_current_object_count_key();
    *csize = logical_quotas_current_data_size_in_bytes_key();

    *kvp.*ccount = str(int(*kvp.*ccount) + *num_objects);
    *kvp.*csize = str(int(*kvp.*csize) + *size_in_bytes);
}

# The general pattern for the PEPs is as follows:
# - Pre-PEPs are used to detect if a certain operation will violate the rules and if so, stop immediately.
#   Pre-PEPs do NOT modify the totals in anyway. They may attach additional metadata needed by the Post-PEP.
# - Post-PEPs are used to update the current totals.

pep_api_rm_coll_pre(*INSTANCE_NAME, *COMM, *INPUT, *OPR_STAT)
{
    *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.coll_name);

    if (*parent_path != "") {
        *kvp = logical_quotas_get_tracking_info(*parent_path);
        logical_quotas_compute_object_count_and_size(*INPUT.coll_name, *count, *size);

        *key = logical_quotas_key(*INPUT.coll_name ++ "_rm_coll_count");
        temporaryStorage.*key = *count;

        *key = logical_quotas_key(*INPUT.coll_name ++ "_rm_coll_data_size");
        temporaryStorage.*key = *size;
    }
}

pep_api_rm_coll_post(*INSTANCE_NAME, *COMM, *INPUT, *OPR_STAT)
{
    *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.coll_name);

    while (*parent_path != "") {
        if (logical_quotas_is_tracking(*parent_path)) {
            *kvp = logical_quotas_get_tracking_info(*parent_path);

            *key = logical_quotas_key(*INPUT.coll_name ++ "_rm_coll_count");
            *count = int(temporaryStorage.*key);

            *key = logical_quotas_key(*INPUT.coll_name ++ "_rm_coll_data_size");
            *size = int(temporaryStorage.*key);

            logical_quotas_add_objects_and_size(*kvp, -*count, -*size);

            *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *parent_path, "-C"), *msg);
            logical_quotas_fail_if_set_key_value_pairs_error(*ec, *parent_path);
        }

        *parent_path = logical_quotas_get_parent_collection(*parent_path);
    }
}

pep_api_data_obj_rename_pre(*INSTANCE_NAME, *COMM, *INPUT)
{
    *src_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.src_obj_path);
    *dst_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.dst_obj_path);

    if (*src_parent_path != *dst_parent_path && !logical_quotas_is_parent_path(*src_parent_path, *dst_parent_path)) {
        while (*dst_parent_path != "") {
            if (logical_quotas_is_tracking(*dst_parent_path)) {
                *kvp = logical_quotas_get_tracking_info(*dst_parent_path);

                *ec = errormsg(msiGetObjType(*INPUT.src_obj_path, *obj_type), *msg);
                logical_quotas_fail_if_object_type_error(*ec, *INPUT.src_obj_path);

                if (*obj_type == "-d") {
                    logical_quotas_fail_if_max_count_violation(*kvp, 1);
                    logical_quotas_fail_if_max_size_violation(*kvp, logical_quotas_get_data_object_size(*INPUT.src_obj_path));
                }
                else if (*obj_type == "-c") {
                    logical_quotas_compute_object_count_and_size(*INPUT.src_obj_path, *count, *size);
                    logical_quotas_fail_if_max_count_violation(*kvp, *count);
                    logical_quotas_fail_if_max_size_violation(*kvp, *size);
                }
                else {
                    logical_quotas_invalid_object_type_error(*INPUT.src_obj_path, *obj_type);
                }
            }

            *dst_parent_path = logical_quotas_get_parent_collection(*dst_parent_path);
        }
    }
}

pep_api_data_obj_rename_post(*INSTANCE_NAME, *COMM, *INPUT)
{
    *src_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.src_obj_path);
    *dst_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.dst_obj_path);

    if (*src_parent_path != *dst_parent_path && !logical_quotas_is_parent_path(*src_parent_path, *dst_parent_path)) {
        while (*dst_parent_path != "") {
            if (logical_quotas_is_tracking(*dst_parent_path)) {
                *kvp = logical_quotas_get_tracking_info(*dst_parent_path);

                *ec = errormsg(msiGetObjType(*INPUT.dst_obj_path, *obj_type), *msg);
                logical_quotas_fail_if_object_type_error(*ec, *INPUT.dst_obj_path);

                if (*obj_type == "-d") {
                    logical_quotas_add_objects_and_size(*kvp, 1, logical_quotas_get_data_object_size(*INPUT.dst_obj_path));
                    *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *dst_parent_path, "-C"), *msg);
                    logical_quotas_fail_if_set_key_value_pairs_error(*ec, *dst_parent_path);
                }
                else if (*obj_type == "-c") {
                    logical_quotas_compute_object_count_and_size(*INPUT.dst_obj_path, *count, *size);
                    logical_quotas_add_objects_and_size(*kvp, *count, *size);
                    *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *dst_parent_path, "-C"), *msg);
                    logical_quotas_fail_if_set_key_value_pairs_error(*ec, *dst_parent_path);
                }
                else {
                    logical_quotas_invalid_object_type_error(*INPUT.dst_obj_path, *obj_type);
                }
            }

            *dst_parent_path = logical_quotas_get_parent_collection(*dst_parent_path);
        }

        while (*src_parent_path != "") {
            if (logical_quotas_is_tracking(*src_parent_path)) {
                *kvp = logical_quotas_get_tracking_info(*src_parent_path);

                *ec = errormsg(msiGetObjType(*INPUT.dst_obj_path, *obj_type), *msg);
                logical_quotas_fail_if_object_type_error(*ec, *INPUT.dst_obj_path);

                if (*obj_type == "-d") {
                    logical_quotas_add_objects_and_size(*kvp, -1, -int(logical_quotas_get_data_object_size(*INPUT.dst_obj_path)));
                    *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *src_parent_path, "-C"), *msg);
                    logical_quotas_fail_if_set_key_value_pairs_error(*ec, *src_parent_path);
                }
                else if (*obj_type == "-c") {
                    logical_quotas_compute_object_count_and_size(*INPUT.dst_obj_path, *count, *size);
                    logical_quotas_add_objects_and_size(*kvp, -*count, -*size);
                    *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *src_parent_path, "-C"), *msg);
                    logical_quotas_fail_if_set_key_value_pairs_error(*ec, *src_parent_path);
                }
                else {
                    logical_quotas_invalid_object_type_error(*INPUT.dst_obj_path, *obj_type);
                }
            }

            *src_parent_path = logical_quotas_get_parent_collection(*src_parent_path);
        }
    }
}

pep_api_data_obj_put_pre(*INSTANCE_NAME, *COMM, *INPUT, *BBUF_INPUT, *OUTPUT)
{
    if (!logical_quotas_data_object_exists(*INPUT.obj_path)) {
        *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.obj_path);

        while (*parent_path != "") {
            if (logical_quotas_is_tracking(*parent_path)) {
                *kvp = logical_quotas_get_tracking_info(*parent_path);
                logical_quotas_fail_if_max_count_violation(*kvp, 1);
                logical_quotas_fail_if_max_size_violation(*kvp, int(*INPUT.data_size));
            }

            *parent_path = logical_quotas_get_parent_collection(*parent_path);
        }
    }
}

pep_api_data_obj_put_post(*INSTANCE_NAME, *COMM, *INPUT, *BBUF_INPUT, *OUTPUT)
{
    *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.obj_path);

    while (*parent_path != "") {
        if (logical_quotas_is_tracking(*parent_path)) {
            *kvp = logical_quotas_get_tracking_info(*parent_path);
            logical_quotas_add_objects_and_size(*kvp, 1, int(*INPUT.data_size));
            *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *parent_path, "-C"), *msg);
            logical_quotas_fail_if_set_key_value_pairs_error(*ec, *parent_path);
        }

        *parent_path = logical_quotas_get_parent_collection(*parent_path);
    }
}

pep_api_data_obj_unlink_pre(*INSTANCE_NAME, *COMM, *INPUT)
{
    *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.obj_path);

    if (*parent_path != "") {
        *ec = msiSplitPath(*INPUT.obj_path, *coll_name, *data_name);
        logical_quotas_fail_if_split_path_error(*ec, *INPUT.obj_path);

        foreach (*row in select DATA_SIZE where COLL_NAME = "*coll_name" and DATA_NAME = "*data_name") {
            *data_size = *row.DATA_SIZE;
        }

        *key = logical_quotas_key("*coll_name/*data_name");
        temporaryStorage.*key = *data_size;
    }
}

pep_api_data_obj_unlink_post(*INSTANCE_NAME, *COMM, *INPUT)
{
    *parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.obj_path);

    if (*parent_path != "") {
        *path = *INPUT.obj_path;
        *key = logical_quotas_key(*path);
        *data_size = int(temporaryStorage.*key);

        while (*parent_path != "") {
            if (logical_quotas_is_tracking(*parent_path)) {
                *kvp = logical_quotas_get_tracking_info(*parent_path);
                logical_quotas_add_objects_and_size(*kvp, -1, -*data_size);
                *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *parent_path, "-C"), *msg);
                logical_quotas_fail_if_set_key_value_pairs_error(*ec, *parent_path);
            }

            *parent_path = logical_quotas_get_parent_collection(*parent_path);
        }
    }
}

pep_api_data_obj_copy_pre(*INSTANCE_NAME, *COMM, *INPUT, *STAT)
{
    *dst_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.dst_obj_path);

    while (*dst_parent_path != "") {
        if (logical_quotas_is_tracking(*dst_parent_path)) {
            *kvp = logical_quotas_get_tracking_info(*dst_parent_path);

            *ec = errormsg(msiGetObjType(*INPUT.src_obj_path, *obj_type), *msg);
            logical_quotas_fail_if_object_type_error(*ec, *INPUT.src_obj_path);

            if (*obj_type == "-d") {
                logical_quotas_fail_if_max_count_violation(*kvp, 1);
                logical_quotas_fail_if_max_size_violation(*kvp, logical_quotas_get_data_object_size(*INPUT.src_obj_path));
            }
            else if (*obj_type == "-c") {
                logical_quotas_compute_object_count_and_size(*INPUT.src_obj_path, *count, *size);
                logical_quotas_fail_if_max_count_violation(*kvp, *count);
                logical_quotas_fail_if_max_size_violation(*kvp, *size);
            }
            else {
                logical_quotas_invalid_object_type_error(*INPUT.src_obj_path, *obj_type);
            }
        }

        *dst_parent_path = logical_quotas_get_parent_collection(*dst_parent_path);
    }
}

pep_api_data_obj_copy_post(*INSTANCE_NAME, *COMM, *INPUT, *STAT)
{
    *dst_parent_path = logical_quotas_get_tracked_parent_collection(*INPUT.dst_obj_path);

    while (*dst_parent_path != "") {
        if (logical_quotas_is_tracking(*dst_parent_path)) {
            *kvp = logical_quotas_get_tracking_info(*dst_parent_path);

            *ec = errormsg(msiGetObjType(*INPUT.src_obj_path, *obj_type), *msg);
            logical_quotas_fail_if_object_type_error(*ec, *INPUT.src_obj_path);

            if (*obj_type == "-d") {
                logical_quotas_add_objects_and_size(*kvp, 1, logical_quotas_get_data_object_size(*INPUT.src_obj_path));
                *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *dst_parent_path, "-C"), *msg);
                logical_quotas_fail_if_set_key_value_pairs_error(*ec, *dst_parent_path);
            }
            else if (*obj_type == "-c") {
                logical_quotas_compute_object_count_and_size(*INPUT.src_obj_path, *count, *size);
                logical_quotas_add_objects_and_size(*kvp, *count, *size);
                *ec = errormsg(msiSetKeyValuePairsToObj(*kvp, *dst_parent_path, "-C"), *msg);
                logical_quotas_fail_if_set_key_value_pairs_error(*ec, *dst_parent_path);
            }
            else {
                logical_quotas_invalid_object_type_error(*INPUT.src_obj_path, *obj_type);
            }
        }

        *dst_parent_path = logical_quotas_get_parent_collection(*dst_parent_path);
    }
}

