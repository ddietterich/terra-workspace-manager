package bio.terra.workspace.service.notsam;

import bio.terra.cloudres.google.cloudresourcemanager.CloudResourceManagerCow;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.common.exception.InternalLogicException;
import bio.terra.workspace.common.utils.GcpUtils;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.iam.model.RoleBinding;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import bio.terra.workspace.service.workspace.CloudSyncRoleMapping;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import com.authzed.api.v1.Core;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.SetIamPolicyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.script.Bindings;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;

@Component
public class AclManager {
  private final Logger logger = LoggerFactory.getLogger(AclManager.class);
  private final CrlService crlService;
  private final CloudSyncRoleMapping cloudSyncRoleMapping;
  private final FeatureConfiguration features;
  private final GcpCloudContextService gcpCloudContextService;
  private final UserManager userManager;

  private final Set<UUID> deletedIds = new ConcurrentSkipListSet<>();
  private final ConcurrentLinkedQueue<UUID> eventQueue = new ConcurrentLinkedQueue<>();

  @Autowired
  public AclManager(
    CrlService crlService,
    CloudSyncRoleMapping cloudSyncRoleMapping,
    FeatureConfiguration features,
    GcpCloudContextService gcpCloudContextService,
    UserManager userManager) {
    this.crlService = crlService;
    this.cloudSyncRoleMapping = cloudSyncRoleMapping;
    this.features = features;
    this.gcpCloudContextService = gcpCloudContextService;
    this.userManager = userManager;
  }

  // Queue an event from the watch flight
  public void workspaceEvent(UUID workspaceId, Core.RelationshipUpdate.Operation operation) {
    switch (operation) {
      case OPERATION_TOUCH, OPERATION_CREATE -> eventQueue.add(workspaceId);
      case OPERATION_DELETE -> deletedIds.add(workspaceId);
      case UNRECOGNIZED, OPERATION_UNSPECIFIED -> {}
    }
  }

  // Pop everything out of the queue into a set. Remove deleted items.
  public Set<UUID> getBatch() {
    Set<UUID> batch = new HashSet<>();
    while (eventQueue.peek() != null) {
      UUID id = eventQueue.poll();
      if (!deletedIds.contains(id)) {
        batch.add(id);
      }
    }
    return batch;
  }

  public void updateProjectAcl(String projectId, List<RoleBinding> roleBindings) {
    CloudResourceManagerCow resourceManagerCow = crlService.getCloudResourceManagerCow();

    try {
      Policy currentPolicy =
        resourceManagerCow
          .projects()
          .getIamPolicy(projectId, new GetIamPolicyRequest())
          .execute();

      // Convert policy bindings to a map
      AclMap currentAclMap = new AclMap(currentPolicy);
      AclMap newAclMap = currentAclMap.makeCopy();

      // Convert roleBindings into bindings and a map. Then compare to policy
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
