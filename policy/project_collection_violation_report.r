project_collection_violation_report {
     get_lifetime_metadata_attribute(*attr)
     get_participating_collection_root(*root)

     # iterate over all participating collections and determine of they are in violation
     foreach(*row in SELECT COLL_NAME, META_COLL_ATTR_VALUE WHERE COLL_NAME like '*root/%' AND META_COLL_ATTR_NAME = '*attr') {
         *coll_name = *row.COLL_NAME
         *lifetime  = *row.META_COLL_ATTR_VALUE
         collection_violates_lifetime_constraint(*coll_name, *lifetime, *violation_time)
         if(*violation_time > 0) {
             writeLine("stdout", "[*coll_name] in violation of lifetime constraint by [*violation_time] days")
         }
     } # foreach
}
INPUT null
OUTPUT ruleExecOut
