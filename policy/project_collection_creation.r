project_collection_creation {
     get_lifetime_metadata_attribute(*attr)
     get_participating_collection_root(*root)

     # handle error case where *name has a trailing /
     trimr(*name, '/')

     *coll_name = *root ++ '/' ++ *name
     # create project collection
     *ec = errorcode(msiCollCreate(*coll_name, 1, *out))
     if(*ec < 0) {
         *ec_str = str(*ec)
         *msg = "Failed to create collection [*coll_name] ec [*ec_str]"
         writeLine("stdout", *msg)
         failmsg(*ec, *msg)
     }

     # set project collection lifetime
     msiset_avu('-C', *coll_name, *attr, str(*lifetime), '')
}
INPUT *name=$, *lifetime=$
OUTPUT ruleExecOut
