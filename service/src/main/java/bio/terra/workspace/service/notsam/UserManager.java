package bio.terra.workspace.service.notsam;

import bio.terra.workspace.service.spice.SpiceService;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserManager {
  private static final Logger logger = LoggerFactory.getLogger(UserManager.class);

  private final SpiceService spiceService;
  private final UserConfiguration userConfiguration;
  private final Map<String, String> emailToSubjectId = new HashMap<>();
  private final Map<String, String> subjectIdToEmail = new HashMap<>();

  private String wsmSaSubjectId = null;

  @Autowired
  public UserManager(UserConfiguration userConfiguration, SpiceService spiceService) {
    this.userConfiguration = userConfiguration;
    this.spiceService = spiceService;
  }

  public String getUserEmail(String subjectId) {
    return subjectIdToEmail.get(subjectId);
  }

  public String getUserSubjectId(String email) {
    return emailToSubjectId.get(email);
  }

  public String addUserAndProxyGroup(String email) {
    String subjectId = addUser(email);
    addToProxyGroup(subjectId, subjectId, "primary");
    return subjectId;
  }

  private String addUser(String email) {
    String subjectId = UUID.randomUUID().toString();
    logger.info("Add email {} as user:{}", email, subjectId);
    emailToSubjectId.put(email, subjectId);
    subjectIdToEmail.put(subjectId, email);
    return subjectId;
  }

  public void addSaToProxyGroup(String proxyGroupId, String petSaEmail) {
    String petSaSubjectId = getUserSubjectId(petSaEmail);
    if (petSaSubjectId == null) {
      petSaSubjectId = addUser(petSaEmail);
    }
    addToProxyGroup(proxyGroupId, petSaSubjectId, "petsa");
  }

  private void addToProxyGroup(String proxyGroupId, String subjectId, String role) {
    logger.info("Creating user {} as {} for proxy group {}", subjectId, role, proxyGroupId);
    spiceService.createRelationship("user", subjectId, "proxy_group", proxyGroupId, role, null);
  }

  // Special add so we can keep track of the WSM SA
  public void addWsmSa(String email) {
    wsmSaSubjectId = addUserAndProxyGroup(email);
  }

  public String getWsmSaSubjectId() {
    return wsmSaSubjectId;
  }

  public void initializeProxyGroups() {
    spiceService.initialize();
    // Configure the users
    for (String userEmail : userConfiguration.getEmails()) {
      addUserAndProxyGroup(userEmail);
    }

  }
}
