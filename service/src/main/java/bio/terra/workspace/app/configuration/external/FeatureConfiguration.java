package bio.terra.workspace.app.configuration.external;

import bio.terra.workspace.common.exception.FeatureNotSupportedException;
import bio.terra.workspace.service.resource.model.WsmResourceStateRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "feature")
public class FeatureConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(FeatureConfiguration.class);

  private boolean azureEnabled;
  private boolean awsEnabled;
  private boolean alpha1Enabled;
  private boolean tpsEnabled;
  private boolean bpmGcpEnabled;
  private boolean temporaryGrantEnabled;
  private boolean dataprocEnabled;
  private WsmResourceStateRule stateRule;

  public boolean isAzureEnabled() {
    return azureEnabled;
  }

  public void setAzureEnabled(boolean azureEnabled) {
    this.azureEnabled = azureEnabled;
  }

  public boolean isAwsEnabled() {
    return awsEnabled;
  }

  public void setAwsEnabled(boolean awsEnabled) {
    this.awsEnabled = awsEnabled;
  }

  public boolean isAlpha1Enabled() {
    return alpha1Enabled;
  }

  public void setAlpha1Enabled(boolean alpha1Enabled) {
    this.alpha1Enabled = alpha1Enabled;
  }

  public boolean isTpsEnabled() {
    return tpsEnabled;
  }

  public void setTpsEnabled(boolean tpsEnabled) {
    this.tpsEnabled = tpsEnabled;
  }

  public boolean isBpmGcpEnabled() {
    return bpmGcpEnabled;
  }

  public void setBpmGcpEnabled(boolean bpmGcpEnabled) {
    this.bpmGcpEnabled = bpmGcpEnabled;
  }

  public boolean isTemporaryGrantEnabled() {
    return temporaryGrantEnabled;
  }

  public void setTemporaryGrantEnabled(boolean temporaryGrantEnabled) {
    this.temporaryGrantEnabled = temporaryGrantEnabled;
  }

  public boolean isDataprocEnabled() {
    return dataprocEnabled;
  }

  public void setDataprocEnabled(boolean dataprocEnabled) {
    this.dataprocEnabled = dataprocEnabled;
  }

  public WsmResourceStateRule getStateRule() {
    return stateRule;
  }

  public FeatureConfiguration setStateRule(WsmResourceStateRule stateRule) {
    this.stateRule = stateRule;
    return this;
  }

  public void azureEnabledCheck() {
    if (!isAzureEnabled()) {
      throw new FeatureNotSupportedException("Azure features are not enabled");
    }
  }

  public void awsEnabledCheck() {
    if (!isAwsEnabled()) {
      throw new FeatureNotSupportedException("AWS features are not enabled");
    }
  }

  public void alpha1EnabledCheck() {
    if (!isAlpha1Enabled()) {
      throw new FeatureNotSupportedException("Alpha1 features are not supported");
    }
  }

  public void tpsEnabledCheck() {
    if (!isTpsEnabled()) {
      throw new FeatureNotSupportedException("Terra Policy Service is not enabled");
    }
  }

  /**
   * Write the feature settings into the log
   *
   * <p>Add an entry here for each new feature
   */
  public void logFeatures() {
    logger.info("Feature: azure-enabled: {}", isAzureEnabled());
    logger.info("Feature: aws-enabled: {}", isAwsEnabled());
    logger.info("Feature: alpha1-enabled: {}", isAlpha1Enabled());
    logger.info("Feature: tps-enabled: {}", isTpsEnabled());
    logger.info("Feature: bpm-gcp-enabled: {}", isBpmGcpEnabled());
    logger.info("Feature: temporary-grant-enabled: {}", isTemporaryGrantEnabled());
    logger.info("Feature: dataproc-enabled: {}", isDataprocEnabled());
    logger.info("Feature: state-rule: {}", getStateRule());
  }
}
