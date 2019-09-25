# Example Usage
# irule -F project_collection_creation.r "*proj_name='alice-project'" "*owner='alice'" "*collab_list='bobby, eve , joe'" *lifetime=0.001 *object_quota=5 *size_quota=500

project_collection_creation {
    create_project_collection(
        *proj_name, *owner, *collab_list,
        *lifetime, *object_quota, *size_quota)
}
INPUT *proj_name=$, *owner=$, *collab_list=$, *lifetime=$, *object_quota=$, *size_quota=$
OUTPUT ruleExecOut
