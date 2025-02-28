package bio.terra.workspace.service.policy;

import bio.terra.common.logging.RequestIdFilter;
import bio.terra.policy.api.TpsApi;
import bio.terra.policy.client.ApiClient;
import bio.terra.policy.client.ApiException;
import bio.terra.policy.model.TpsComponent;
import bio.terra.policy.model.TpsLocation;
import bio.terra.policy.model.TpsObjectType;
import bio.terra.policy.model.TpsPaoCreateRequest;
import bio.terra.policy.model.TpsPaoExplainResult;
import bio.terra.policy.model.TpsPaoGetResult;
import bio.terra.policy.model.TpsPaoReplaceRequest;
import bio.terra.policy.model.TpsPaoSourceRequest;
import bio.terra.policy.model.TpsPaoUpdateRequest;
import bio.terra.policy.model.TpsPaoUpdateResult;
import bio.terra.policy.model.TpsPolicyInputs;
import bio.terra.policy.model.TpsRegions;
import bio.terra.policy.model.TpsUpdateMode;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.app.configuration.external.PolicyServiceConfiguration;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.policy.exception.PolicyServiceAPIException;
import bio.terra.workspace.service.policy.exception.PolicyServiceAuthorizationException;
import bio.terra.workspace.service.policy.exception.PolicyServiceDuplicateException;
import bio.terra.workspace.service.policy.exception.PolicyServiceNotFoundException;
import bio.terra.workspace.service.policy.model.PolicyExplainResult;
import bio.terra.workspace.service.resource.exception.PolicyConflictException;
import bio.terra.workspace.service.workspace.WorkspaceService;
import bio.terra.workspace.service.workspace.model.CloudPlatform;
import io.opencensus.contrib.http.jaxrs.JaxrsClientExtractor;
import io.opencensus.contrib.http.jaxrs.JaxrsClientFilter;
import io.opencensus.contrib.spring.aop.Traced;
import io.opencensus.trace.Tracing;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.annotation.Nullable;
import javax.ws.rs.client.Client;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class TpsApiDispatch {
  private static final Logger logger = LoggerFactory.getLogger(TpsApiDispatch.class);
  private final FeatureConfiguration features;
  private final PolicyServiceConfiguration policyServiceConfiguration;
  private final Client commonHttpClient;

  @Autowired
  public TpsApiDispatch(
      FeatureConfiguration features, PolicyServiceConfiguration policyServiceConfiguration) {
    this.features = features;
    this.policyServiceConfiguration = policyServiceConfiguration;
    this.commonHttpClient =
        new ApiClient()
            .getHttpClient()
            .register(
                new JaxrsClientFilter(
                    new JaxrsClientExtractor(), Tracing.getPropagationComponent().getB3Format()));

    logger.info("TPS base path: '{}'", policyServiceConfiguration.getBasePath());
  }

  // -- Policy Attribute Object Interface --
  @Traced
  public void createPao(UUID workspaceUuid, @Nullable TpsPolicyInputs policyInputs) {
    features.tpsEnabledCheck();
    TpsPolicyInputs inputs = (policyInputs == null) ? new TpsPolicyInputs() : policyInputs;

    TpsApi tpsApi = policyApi();
    try {
      tpsApi.createPao(
          new TpsPaoCreateRequest()
              .objectId(workspaceUuid)
              .component(TpsComponent.WSM)
              .objectType(TpsObjectType.WORKSPACE)
              .attributes(inputs));
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  // Since policy attributes were added later in development, not all existing
  // workspaces have an associated policy attribute object. This function creates
  // an empty one if it does not exist.
  @Traced
  public void createPaoIfNotExist(UUID workspaceId) {
    Optional<TpsPaoGetResult> pao = getPaoIfExists(workspaceId);
    if (pao.isPresent()) {
      return;
    }
    // Workspace doesn't have a PAO, so create an empty one for it.
    createPao(workspaceId, null);
  }

  @Traced
  public void deletePao(UUID workspaceUuid) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    try {
      try {
        tpsApi.deletePao(workspaceUuid);
      } catch (ApiException e) {
        throw convertApiException(e);
      }
    } catch (PolicyServiceNotFoundException e) {
      // Not found is not an error as far as WSM is concerned.
    }
  }

  private Optional<TpsPaoGetResult> getPaoIfExists(UUID workspaceUuid) {
    features.tpsEnabledCheck();
    try {
      TpsPaoGetResult pao = getPao(workspaceUuid);
      return Optional.of(pao);
    } catch (PolicyServiceNotFoundException e) {
      return Optional.empty();
    }
  }

  @Traced
  public TpsPaoGetResult getPao(UUID workspaceUuid) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    try {
      return tpsApi.getPao(workspaceUuid);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  @Traced
  public TpsPaoUpdateResult linkPao(
      UUID workspaceUuid, UUID sourceObjectId, TpsUpdateMode updateMode) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();

    try {
      return tpsApi.linkPao(
          new TpsPaoSourceRequest().sourceObjectId(sourceObjectId).updateMode(updateMode),
          workspaceUuid);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  @Traced
  public TpsPaoUpdateResult mergePao(
      UUID workspaceUuid, UUID sourceObjectId, TpsUpdateMode updateMode) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();

    try {
      return tpsApi.mergePao(
          new TpsPaoSourceRequest().sourceObjectId(sourceObjectId).updateMode(updateMode),
          workspaceUuid);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  @Traced
  public TpsPaoUpdateResult replacePao(
      UUID workspaceUuid, TpsPolicyInputs policyInputs, TpsUpdateMode updateMode) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();

    try {
      return tpsApi.replacePao(
          new TpsPaoReplaceRequest().newAttributes(policyInputs).updateMode(updateMode),
          workspaceUuid);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  @Traced
  public TpsPaoUpdateResult updatePao(
      UUID workspaceUuid,
      TpsPolicyInputs addAttributes,
      TpsPolicyInputs removeAttributes,
      TpsUpdateMode updateMode) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    try {
      return tpsApi.updatePao(
          new TpsPaoUpdateRequest()
              .addAttributes(addAttributes)
              .removeAttributes(removeAttributes)
              .updateMode(updateMode),
          workspaceUuid);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  @Traced
  public List<String> listValidRegions(UUID workspaceId, CloudPlatform platform) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    TpsRegions tpsRegions;
    try {
      tpsRegions = tpsApi.listValidRegions(workspaceId, platform.toTps());
    } catch (ApiException e) {
      throw convertApiException(e);
    }
    if (tpsRegions != null) {
      return tpsRegions.stream().toList();
    }
    return new ArrayList<>();
  }

  @Traced
  public List<String> listValidRegionsForPao(TpsPaoGetResult tpsPao, CloudPlatform platform) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    TpsRegions tpsRegions;
    try {
      tpsRegions = tpsApi.listValidByPolicyInput(tpsPao.getEffectiveAttributes(), platform.toTps());
    } catch (ApiException e) {
      throw convertApiException(e);
    }
    if (tpsRegions != null) {
      return tpsRegions.stream().toList();
    }
    return new ArrayList<>();
  }

  public PolicyExplainResult explain(
      UUID workspaceId,
      int depth,
      WorkspaceService workspaceService,
      AuthenticatedUserRequest userRequest) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    try {
      TpsPaoExplainResult tpsResult = tpsApi.explainPao(workspaceId, depth);
      return new PolicyExplainResult(
          tpsResult.getObjectId(),
          tpsResult.getDepth(),
          // Fetches WSM object specific information (access, name, properties of a WSM object
          // i.e. workspace and put it in the wsm policy object.
          Optional.ofNullable(tpsResult.getExplainObjects())
              .orElse(Collections.emptyList())
              .stream()
              .map(
                  source ->
                      TpsApiConversionUtils.buildWsmPolicyObject(
                          source, workspaceService, userRequest))
              .toList(),
          Optional.ofNullable(tpsResult.getExplanation()).orElse(Collections.emptyList()));
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  public TpsLocation getLocationInfo(CloudPlatform platform, String location) {
    features.tpsEnabledCheck();
    TpsApi tpsApi = policyApi();
    try {
      return tpsApi.getLocationInfo(platform.toTps(), location);
    } catch (ApiException e) {
      throw convertApiException(e);
    }
  }

  private ApiClient getApiClient(String accessToken) {
    ApiClient client =
        new ApiClient()
            .setHttpClient(commonHttpClient)
            .addDefaultHeader(
                RequestIdFilter.REQUEST_ID_HEADER, MDC.get(RequestIdFilter.REQUEST_ID_MDC_KEY));
    client.setAccessToken(accessToken);
    return client;
  }

  private TpsApi policyApi() {
    try {
      return new TpsApi(
          getApiClient(policyServiceConfiguration.getAccessToken())
              .setBasePath(policyServiceConfiguration.getBasePath()));
    } catch (IOException e) {
      throw new PolicyServiceAuthorizationException(
          String.format(
              "Error reading or parsing credentials file at %s",
              policyServiceConfiguration.getClientCredentialFilePath()),
          e.getCause());
    }
  }

  private RuntimeException convertApiException(ApiException ex) {
    if (ex.getCode() == HttpStatus.UNAUTHORIZED.value()) {
      return new PolicyServiceAuthorizationException(
          "Not authorized to access Terra Policy Service", ex.getCause());
    } else if (ex.getCode() == HttpStatus.NOT_FOUND.value()) {
      return new PolicyServiceNotFoundException("Policy service returns not found exception", ex);
    } else if (ex.getCode() == HttpStatus.BAD_REQUEST.value()
        && StringUtils.containsIgnoreCase(ex.getMessage(), "duplicate")) {
      return new PolicyServiceDuplicateException(
          "Policy service throws duplicate object exception", ex);
    } else if (ex.getCode() == HttpStatus.CONFLICT.value()) {
      return new PolicyConflictException("Policy service throws conflict exception", ex);
    } else {
      return new PolicyServiceAPIException(ex);
    }
  }
}
