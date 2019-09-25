project_collection_creation {
    create_project_collection(
        *proj_name, *owner, *collab_list,
        *lifetime, *object_quota, *size_quota)
}
INPUT *proj_name=$, *owner=$, *collab_list=$, *lifetime=$, *object_quota=$, *size_quota=$
OUTPUT ruleExecOut
