# iRODS Collection Lifetime Policy
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# This is a policy implementation which provides the identification and reporting of collections which
# have exceeded their lifetimes.  A collection may be tagged with a metadata attribute and value which
# identifies the lifetime of the collection in days.
#
# An additional policy may be called to generate a report which lists any collections which are in violation
# of their determined lifetime.
#
# Data objects which are placed into a collection with the lifetime metadata tag will also inherit metadata which
# states the lifetime and parent collection
#

# Single point of truth for an error value
get_error_value(*err) { *err = "ERROR_VALUE" }

# The code to return for the rule engine plugin framework to look for additional PEPs to fire.
RULE_ENGINE_CONTINUE { 5000000 }

# Error code if input is incorrect
SYS_INVALID_INPUT_PARAM { -130000 }

# admin privilege value
LOCAL_PRIV_USER_AUTH { 5 }

# metadata attribute driving the policy in units of days, fractions of a day are allowed: e.g. 0.01
project_collection_lifetime_attribute { "irods::collection::lifetime" }

# defined root collection to trigger policy - removes catalog load
# NOTE: assumption is made that the collection does NOT end in a /
#project_collection_root { "/dirisa.ac.za/projects/" }
project_collection_root { "/tempZone/projects" }

# defined violating root collection to trigger read/write prevention
# NOTE: assumption is made that the collection does NOT end in a /
#project_collection_violating_root { "/dirisa.ac.za/violating_projects/" }
project_collection_violating_root{ "/tempZone/violating_projects" }

###################################################################
# Policy Implementation for External Invocation

# Business logic for project creation - this rule depends on the logical quota rule base
create_project_collection(*proj_name, *owner, *collab_list, *lifetime, *object_quota, *size_quota) {
     *attr = project_collection_lifetime_attribute()
     *root = project_collection_root()

     # handle error case where *name has a trailing /
     *proj_name = trimr(*proj_name, '/')

     # build fully qualified project path
     *coll_name = *root ++ '/' ++ *proj_name

     # create project collection
     *ec = errorcode(msiCollCreate(*coll_name, 1, *out))
     if(*ec < 0) {
         *ec_str = str(*ec)
         *msg = "Failed to create collection [*coll_name] ec [*ec_str]"
         writeLine("stdout", *msg)
         failmsg(*ec, *msg)
     }

     # set project collection lifetime metadata
     msiset_avu('-C', *coll_name, *attr, str(*lifetime), '')

     # set project collection logical quota
     logical_quotas_init(*coll_name, *object_quota, *size_quota)

     # set inherit flag
     msiSetACL("recursive", "inherit", "", *coll_name)

     # set owner of the project
     msiSetACL("recursive", "own", *owner, *coll_name)

     # set modify for all collaborators
     *split_list = split(*collab_list, ",")
     while(size(*split_list) > 0) {
         # pull head of list
         *name = str(hd(*split_list))

         # subset remainder of list
         *split_list = tl(*split_list)

         # chomp space
         *name = triml(*name, ' ')
         *name = trimr(*name, ' ')

         # set write permission for collaborator
         msiSetACL("recursive", "write", *name, *coll_name)
     }
} # create_project_collection

# Query for all collections with the lifetime attribute.  Determine if any lifetimes
# have grown beyond their contstraint
collection_violates_lifetime_constraint(*coll_name, *lifetime, *violation_time) {
    get_error_value(*err_val)
    get_error_value(*create_time)
    *violation_time = 0

    foreach( *row in SELECT COLL_CREATE_TIME WHERE COLL_NAME = '*coll_name') {
        *create_time = *row.COLL_CREATE_TIME
    }

    if(*err_val == *create_time) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Failed to get COLL_CREATE_TIME for [*coll_name]")
    }

    if(*create_time != *err_val) {
        # 24hrs * 60 minutes * 60 seconds
        *seconds_per_day = 24.0 * 60.0 * 60.0

        *lifetime_days_dbl = double(*lifetime)

        msiGetSystemTime(*sys_time, '')
        *clean_sys_time = triml(*sys_time, "0")
        *cleaner_sys_time = triml(*clean_sys_time, " ")
        *sys_time_dbl = double(*cleaner_sys_time)
        *sys_time_days_dbl = *sys_time_dbl / *seconds_per_day

        *clean_create_time = triml(*create_time, "0")
        *cleaner_create_time = triml(*clean_create_time, " ")
        *create_time_dbl = double(*cleaner_create_time)
        *create_time_days_dbl = *create_time_dbl / *seconds_per_day

        *total_days_dbl = *create_time_days_dbl + *lifetime_days_dbl
        if(*sys_time_days_dbl > *total_days_dbl) {
            *violation_time = *sys_time_days_dbl - *total_days_dbl
        }
    }

} # collection_violates_lifetime_constraint

# Query for all project collections given the root collection and the metadata attribute
# defining the lifetime of the collection.  Print any collections which are older than the
# given lifetime of the project
project_collection_list_violations {
     *attr = project_collection_lifetime_attribute()
     *root = project_collection_root()

     # iterate over all participating collections and determine of they are in violation
     foreach(*row in SELECT COLL_NAME, META_COLL_ATTR_VALUE WHERE COLL_NAME like '*root/%' AND META_COLL_ATTR_NAME = '*attr') {
         *coll_name = *row.COLL_NAME
         *lifetime  = *row.META_COLL_ATTR_VALUE
         collection_violates_lifetime_constraint(*coll_name, *lifetime, *violation_time)
         if(*violation_time > 0) {
             writeLine("stdout", "[*coll_name] in violation of lifetime constraint by [*violation_time] days")
         }
     } # foreach
} # project_collection_list_violations

###################################################################
# Helper Functions
get_collection_lifetime(*collection, *lifetime) {
    get_error_value(*err_val)
    get_error_value(*lifetime)
    *attr = project_collection_lifetime_attribute()

    foreach( *row in SELECT META_COLL_ATTR_VALUE WHERE META_COLL_ATTR_NAME = '*attr' AND COLL_NAME = '*collection') {
        *lifetime = *row.META_COLL_ATTR_VALUE
    }
} # get_collection_lifetime

get_project_collection_from_path(*logical_path, *project_collection) {
    *root = project_collection_root()
    get_error_value(*project_collection)
    get_error_value(*parent)
    *full_path = *logical_path

    while(*parent != *root && *parent != "/") {
        *ec = errormsg(msiSplitPath(*full_path, *parent, *child), *msg);
        if (*ec < 0) {
            failmsg(*ec, *msg);
        }

        if(*parent == *root) {
            *project_collection = *parent ++ "/" ++ *child
        }
        else {
            *full_path = *parent
        }
    } # while

} # get_project_collection_from_path

###################################################################
# Policy Implemetation

# metadata inheritance
pep_api_data_obj_put_post(*INSTANCE_NAME, *COMM, *DATAOBJINP, *BBUFF, *PORTAL_OPR_OUT) {
    get_error_value(*err_val)
    *logical_path = *DATAOBJINP.obj_path
    *root = project_collection_root()

    if(*logical_path like *root++"/*") {
        get_project_collection_from_path(*logical_path, *project_collection)
        get_collection_lifetime(*project_collection, *lifetime)
        if(*err_val != *lifetime) {
            # apply metadata to data object
            *attr = project_collection_lifetime_attribute()
            msiset_avu("-d", *logical_path, *attr, *project_collection, *lifetime)
        }
    }
    RULE_ENGINE_CONTINUE
} # pep_api_data_obj_put_post

# prevent reads, writes, and moves to the violating project root
prevent_operation_on_violating_project_collection(*CTX) {
    *logical_path = *CTX.logical_path
    *user_auth_flag = *CTX.user_auth_info_auth_flag
    *root = project_collection_violating_root()

    *match = (*logical_path like *root++"/*")
    *priv = (int(*user_auth_flag) < LOCAL_PRIV_USER_AUTH)

    if(*match && *priv) {
        failmsg(SYS_INVALID_INPUT_PARAM, "Unable to access violating project collections")
    }
}

pep_resource_open_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_open_pre

pep_resource_create_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_create_pre

pep_resource_unlink_pre(*INSTANCE, *CTX, *OUT) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_unlink_pre

pep_resource_rename_pre(*INSTANCE, *CTX, *OUT, *FILENAME) {
    prevent_operation_on_violating_project_collection(*CTX)
    RULE_ENGINE_CONTINUE
} # pep_resource_rename_pre

