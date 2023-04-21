package bio.terra.workspace.service.notsam;

import bio.terra.cloudres.google.cloudresourcemanager.CloudResourceManagerCow;
import bio.terra.workspace.common.utils.GcpUtils;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.model.RoleBinding;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import bio.terra.workspace.service.workspace.CloudSyncRoleMapping;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.SetIamPolicyRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Manage ACLs on projects */
@Component
public class AclManagerProject {
  private final CrlService crlService;
  private final CloudSyncRoleMapping cloudSyncRoleMapping;

  @Autowired
  public AclManagerProject(
    CrlService crlService,
    CloudSyncRoleMapping cloudSyncRoleMapping) {
    this.crlService = crlService;
    this.cloudSyncRoleMapping = cloudSyncRoleMapping;
  }

  public void updateProjectAcl(String projectId, List<RoleBinding> roleBindings) {
    CloudResourceManagerCow resourceManagerCow = crlService.getCloudResourceManagerCow();

    try {
      Policy currentPolicy =
        resourceManagerCow
          .projects()
          .getIamPolicy(projectId, new GetIamPolicyRequest())
          .execute();

      // Convert policy bindings to a canonical AclMap
      var currentAclMap = new AclMap();
      List<Binding> bindings = currentPolicy.getBindings();
      if (bindings != null) {
        for (Binding binding : bindings) {
          currentAclMap.setRole(binding.getRole(), binding.getMembers());
        }
      }

      // Convert roleBindings into bindings and a map. Then compare to policy
      var newAclMap = currentAclMap.makeCopy();
      Map<WsmIamRole, CustomGcpIamRole> projectRoleMap = cloudSyncRoleMapping.getCustomGcpProjectIamRoles();
      for (RoleBinding roleBinding : roleBindings) {
        // Only include roles that should be on the ACL
        if (!isAclRole(roleBinding.role())) {
          continue;
        }

        List<String> members = new ArrayList<>();
        for (String user : roleBinding.users()) {
          if (user.contains(".gserviceaccount.")) {
            members.add(GcpUtils.toSaMember(user));
          } else {
            members.add(GcpUtils.toUserMember(user));
          }
        }

        String role = projectRoleMap.get(roleBinding.role()).getFullyQualifiedRoleName(projectId);
        newAclMap.setRole(role, members);
      }

      // If nothing has changed, we are done
      if (currentAclMap.equals(newAclMap)) {
        return;
      }

      // Construct the new policy and do the update
      Policy newPolicy = new Policy();
      List<Binding> newBindings = new ArrayList<>();
      for (Map.Entry<String, List<String>> entry : newAclMap.getEntrySet()) {
        Binding binding = new Binding();
        binding.setRole(entry.getKey());
        binding.setMembers(entry.getValue());
        newBindings.add(binding);
      }
      newPolicy.setBindings(newBindings);

      SetIamPolicyRequest request = new SetIamPolicyRequest().setPolicy(newPolicy);
      resourceManagerCow.projects().setIamPolicy(projectId, request).execute();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Test if an IAM role is maintained on the GCP ACL
   * @param role role to test
   * @return true if the role is used on the ACL
   */
  public boolean isAclRole(WsmIamRole role) {
    return (role == WsmIamRole.OWNER
      || role == WsmIamRole.WRITER
      || role == WsmIamRole.READER);
  }

}
