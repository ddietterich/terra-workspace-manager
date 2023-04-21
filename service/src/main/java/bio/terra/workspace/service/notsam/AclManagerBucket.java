package bio.terra.workspace.service.notsam;

import bio.terra.cloudres.google.storage.StorageCow;
import bio.terra.workspace.common.exception.InternalLogicException;
import bio.terra.workspace.common.utils.GcpUtils;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.model.ControlledResourceIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRoleMapping;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.gcsbucket.ControlledGcsBucketResource;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import bio.terra.workspace.service.workspace.CloudSyncRoleMapping;
import com.google.cloud.Binding;
import com.google.cloud.Policy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Manage ACLs on projects */
@Component
public class AclManagerBucket {
  private final CrlService crlService;

  @Autowired
  public AclManagerBucket(CrlService crlService, CloudSyncRoleMapping cloudSyncRoleMapping) {
    this.crlService = crlService;
  }

  public void updateBucketAcl(
      ControlledGcsBucketResource resource,
      String projectId,
      List<NotSamService.ResourceRoleBinding> roleBindings) {
    StorageCow wsmSaStorageCow = crlService.createStorageCow(projectId);
    Policy currentPolicy = wsmSaStorageCow.getIamPolicy(resource.getBucketName());

    var currentAclMap = new AclMap();
    List<Binding> bindings = currentPolicy.getBindingsList();
    if (bindings != null) {
      for (Binding binding : bindings) {
        currentAclMap.setRole(binding.getRole(), binding.getMembers());
      }
    }

    AclMap newAclMap = currentAclMap.makeCopy();
    // We don't have to filter in this case, because the call only gets the relevant roles
    for (NotSamService.ResourceRoleBinding roleBinding : roleBindings) {
      List<String> members = new ArrayList<>();
      for (String user : roleBinding.users()) {
        if (user.contains(".gserviceaccount.")) {
          members.add(GcpUtils.toSaMember(user));
        } else {
          members.add(GcpUtils.toUserMember(user));
        }
      }

      String role = getCustomRole(roleBinding.role(), resource.getResourceType(), projectId);
      newAclMap.setRole(role, members);
    }

    // If nothing has changed, we are done
    if (currentAclMap.equals(newAclMap)) {
      return;
    }

    List<Binding> newBindings = new ArrayList<>();
    for (Map.Entry<String, List<String>> entry : newAclMap.getEntrySet()) {
      newBindings.add(
          Binding.newBuilder().setRole(entry.getKey()).setMembers(entry.getValue()).build());
    }

    Policy newPolicy = Policy.newBuilder().setBindings(newBindings).build();

    wsmSaStorageCow.setIamPolicy(resource.getBucketName(), newPolicy);
  }

  public String getCustomRole(
      ControlledResourceIamRole resourceRole, WsmResourceType resourceType, String projectId) {
    CustomGcpIamRole customRole =
        CustomGcpIamRoleMapping.CUSTOM_GCP_RESOURCE_IAM_ROLES.get(resourceType, resourceRole);
    if (customRole == null) {
      throw new InternalLogicException(
          String.format("Missing custom GCP resource role %s", resourceRole));
    }
    return customRole.getFullyQualifiedRoleName(projectId);
  }
}
