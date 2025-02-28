package bio.terra.workspace.service.resource.controlled.cloud.gcp.gcsbucket;

import bio.terra.cloudres.google.storage.StorageCow;
import bio.terra.stairway.FlightContext;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.Step;
import bio.terra.stairway.StepResult;
import bio.terra.stairway.StepStatus;
import bio.terra.stairway.exception.RetryException;
import bio.terra.workspace.common.utils.FlightUtils;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.notsam.NotSamService;
import bio.terra.workspace.service.resource.controlled.ControlledResourceService;
import bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys;
import bio.terra.workspace.service.workspace.model.GcpCloudContext;
import com.google.cloud.Policy;
import com.google.cloud.storage.StorageException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

/** A step for granting cloud permissions on resources to workspace members. */
public class GcsBucketCloudSyncStep implements Step {
  private final ControlledGcsBucketResource resource;
  private final NotSamService notSamService;

  public GcsBucketCloudSyncStep(
      NotSamService notSamService,
      ControlledGcsBucketResource resource) {
    this.resource = resource;
    this.notSamService = notSamService;
  }

  @Override
  public StepResult doStep(FlightContext flightContext)
      throws InterruptedException, RetryException {
    FlightMap workingMap = flightContext.getWorkingMap();
    GcpCloudContext cloudContext =
      FlightUtils.getRequired(workingMap, ControlledResourceKeys.GCP_CLOUD_CONTEXT, GcpCloudContext.class);

    try {
      notSamService.updateBucketAcl(resource, cloudContext.getGcpProjectId());
    } catch (StorageException e) {
      if (HttpStatus.valueOf(e.getCode()).is4xxClientError()) {
        return new StepResult(StepStatus.STEP_RESULT_FAILURE_RETRY, e);
      }
      return new StepResult(StepStatus.STEP_RESULT_FAILURE_FATAL, e);
    }

    return StepResult.getStepResultSuccess();
  }

  /**
   * Because the resource will be deleted when other steps are undone, we don't need to undo
   * permissions.
   */
  @Override
  public StepResult undoStep(FlightContext flightContext) throws InterruptedException {
    return StepResult.getStepResultSuccess();
  }
}
