package bio.terra.workspace.service.notsam;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * WSM Applications are clients of WSM that create a special class of resources: application-owned
 * resources. Being a configured WSM application gives the client control over the lifecycle and
 * configuration of their resources. Workspace users do not have control the way they would for
 * user-created resources. WSM application in this context refers to some piece of middleware that
 * may or may not interact with what a user would call an application.
 */
@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "workspace.users")
public class UserConfiguration {
  List<String> emails;

  public List<String> getEmails() {
    return emails;
  }

  public void setEmails(List<String> emails) {
    this.emails = emails;
  }
}
