package bio.terra.workspace.service.workspace.flight.gcp;

import static bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.GCP_PROJECT_ID;

import bio.terra.cloudres.google.cloudresourcemanager.CloudResourceManagerCow;
import bio.terra.stairway.FlightContext;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.common.exception.InternalLogicException;
import bio.terra.workspace.common.utils.GcpUtils;
import bio.terra.workspace.service.grant.GrantService;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.notsam.AclManager;
import bio.terra.workspace.service.notsam.NotSamService;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import bio.terra.workspace.service.workspace.CloudSyncRoleMapping;
import bio.terra.workspace.service.workspace.exceptions.RetryableCrlException;
import bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.SetIamPolicyRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Step} that grants GCP IAM permissions to Sam policy groups.
 *
 * <p>This step will grant GCP IAM roles to the google groups underlying Sam policies. It follows a
 * read-modify-write pattern using GCP's field eTag to ensure the write does not clobber other
 * changes. The read-modify-write pattern is necessary to support existing IAM groups which the
 * Buffer Service may grant on projects before handing them out.
 *
 * <p>The "modify" part of this step specifically adds GCP bindings as specified in {@link
 * CloudSyncRoleMapping}. Note that the bindings list sent to GCP may contain multiple entries with
 * the same role. This is valid, though GCP will condense them into one binding per role internally.
 *
 * <p>TODO(PF-624): this step is only used for granting project-level permissions. Once we
 * transition to fully using resource-level permissions, this step can be deleted.
 */
public class GcpCloudSyncStep implements Step {
  private final Logger logger = LoggerFactory.getLogger(GcpCloudSyncStep.class);

  private final NotSamService notSamService;
  private final UUID workspaceUuid;

  public GcpCloudSyncStep(
    NotSamService notSamService,
    UUID workspaceUuid) {
    this.notSamService = notSamService;
    this.workspaceUuid = workspaceUuid;
  }

  @Override
  public StepResult doStep(FlightContext flightContext)
      throws InterruptedException, RetryException {
    String gcpProjectId = flightContext.getWorkingMap().get(GCP_PROJECT_ID, String.class);

    notSamService.updateProjectAcl(workspaceUuid, gcpProjectId);
    return StepResult.getStepResultSuccess();
  }

  /**
   * Because the project will be deleted when other steps are undone, we don't need to undo
   * permissions.
   */
  @Override
  public StepResult undoStep(FlightContext flightContext) throws InterruptedException {
    return StepResult.getStepResultSuccess();
  }
}
