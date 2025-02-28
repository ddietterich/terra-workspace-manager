package bio.terra.workspace.service.resource.referenced.flight.clone;

import bio.terra.stairway.Flight;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.RetryRule;
import bio.terra.workspace.common.utils.FlightBeanBag;
import bio.terra.workspace.common.utils.FlightUtils;
import bio.terra.workspace.common.utils.RetryRules;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.job.JobMapKeys;
import bio.terra.workspace.service.policy.flight.MergePolicyAttributesDryRunStep;
import bio.terra.workspace.service.policy.flight.MergePolicyAttributesStep;
import bio.terra.workspace.service.policy.flight.ValidateGroupPolicyAttributesStep;
import bio.terra.workspace.service.policy.flight.ValidateWorkspaceAgainstPolicyStep;
import bio.terra.workspace.service.resource.model.CloningInstructions;
import bio.terra.workspace.service.resource.referenced.model.ReferencedResource;
import bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys;
import bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys.ControlledResourceKeys;
import java.util.Optional;
import java.util.UUID;

/** A flight to clone a referenced resource including policy checks, if available. */
public class CloneReferencedResourceFlight extends Flight {
  /**
   * Flight to clone a reference resource.
   *
   * @param inputParameters FlightMap of the inputs for the flight
   * @param beanBag Anonymous context meaningful to the application using Stairway
   */
  public CloneReferencedResourceFlight(FlightMap inputParameters, Object beanBag) {
    super(inputParameters, beanBag);

    FlightBeanBag appContext = FlightBeanBag.getFromObject(beanBag);
    RetryRule shortDatabaseRetryRule = RetryRules.shortDatabase();

    UUID destinationWorkspaceId =
        FlightUtils.getRequired(
            inputParameters, ControlledResourceKeys.DESTINATION_WORKSPACE_ID, UUID.class);

    ReferencedResource sourceResource =
        FlightUtils.getRequired(
            inputParameters,
            WorkspaceFlightMapKeys.ResourceKeys.RESOURCE,
            ReferencedResource.class);

    ReferencedResource destinationResource =
        FlightUtils.getRequired(
            inputParameters,
            WorkspaceFlightMapKeys.ResourceKeys.DESTINATION_RESOURCE,
            ReferencedResource.class);

    CloningInstructions cloningInstructions =
        FlightUtils.getRequired(
            inputParameters,
            WorkspaceFlightMapKeys.ResourceKeys.CLONING_INSTRUCTIONS,
            CloningInstructions.class);

    AuthenticatedUserRequest userRequest =
        FlightUtils.getRequired(
            inputParameters,
            JobMapKeys.AUTH_USER_INFO.getKeyName(),
            AuthenticatedUserRequest.class);

    boolean mergePolicies =
        Optional.ofNullable(
                inputParameters.get(WorkspaceFlightMapKeys.MERGE_POLICIES, Boolean.class))
            .orElse(false);

    if (mergePolicies) {
      addStep(
          new MergePolicyAttributesDryRunStep(
              sourceResource.getWorkspaceId(),
              destinationWorkspaceId,
              cloningInstructions,
              appContext.getTpsApiDispatch()));

      addStep(
          new ValidateWorkspaceAgainstPolicyStep(
              destinationWorkspaceId,
              sourceResource.getResourceType().getCloudPlatform(),
              null, // referenced resources don't have a location.
              userRequest,
              appContext.getResourceDao(),
              appContext.getTpsApiDispatch()));

      addStep(
          new ValidateGroupPolicyAttributesStep(
              destinationWorkspaceId, appContext.getTpsApiDispatch()));

      addStep(
          new MergePolicyAttributesStep(
              sourceResource.getWorkspaceId(),
              destinationWorkspaceId,
              cloningInstructions,
              appContext.getTpsApiDispatch()));
    }

    addStep(
        new CloneReferenceResourceStep(
            userRequest,
            appContext.getReferencedResourceService(),
            sourceResource,
            destinationResource),
        shortDatabaseRetryRule);
  }
}
