package bio.terra.workspace.service.notsam;

import bio.terra.workspace.common.utils.GcpUtils;
import bio.terra.workspace.service.iam.model.RoleBinding;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.common.base.Objects;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AclMap holds a mapping from role name to list of members
 * The members are in the Binding form; e.g., "user:email" and "serviceAccount:email"
 */
public class AclMap {
  private final Map<String, List<String>> roleMap = new HashMap<>();


  public AclMap() {}

  public AclMap makeCopy() {
    AclMap mapCopy = new AclMap();
    for (var entry : roleMap.entrySet()) {
      List<String> memberCopy = new ArrayList<>(entry.getValue());
      mapCopy.setRole(entry.getKey(), memberCopy);
    }
    return mapCopy;
  }

  public void setRole(String role, List<String> members) {
    if (members.size() > 0) {
      roleMap.put(role, members);
    } else {
      roleMap.remove(role);
    }
  }

  public Set<Map.Entry<String, List<String>>> getEntrySet() {
    return roleMap.entrySet();
  }

  // Construct the map from notsam
  public AclMap(List<RoleBinding> roleBindings, String projectId, Map<WsmIamRole, CustomGcpIamRole> projectRoleMap) {
    for (RoleBinding roleBinding : roleBindings) {
      List<String> members = new ArrayList<>();
      for (String user : roleBinding.users()) {
        if (user.contains(".gserviceaccount.")) {
          members.add(GcpUtils.toSaMember(user));
        } else {
          members.add(GcpUtils.toUserMember(user));
        }
      }

      // Only make an entry in the map if it has members
      if (members.size() > 0) {
        String role = projectRoleMap.get(roleBinding.role()).getFullyQualifiedRoleName(projectId);
        roleMap.put(role, members);
      }
    }
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof AclMap aclMap)) return false;

    // Are the roles the same
    if (roleMap.keySet().size() != aclMap.roleMap.keySet().size() ||
       (!roleMap.keySet().containsAll(aclMap.roleMap.keySet()))) {
      return false;
    }

    // Are the members in each role the same
    for (var entry : roleMap.entrySet()) {
      if (!listsAreEqual(entry.getValue(), aclMap.roleMap.get(entry.getKey()))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(roleMap);
  }

  /**
   * Compare two string lists to see if they have the same string in any order
   * @param listOne one list
   * @param listTwo two list
   * @return true if the lists are equal
   */
  private boolean listsAreEqual(List<String> listOne, List<String> listTwo) {
    if (listOne.size() != listTwo.size()) {
      return false;
    }
    List<String> differences = new ArrayList<>(listOne);
    differences.removeAll(listTwo);
    return (differences.size() == 0);
  }
}
