/*
 * Copyright 2020-2022 Foreseeti AB <https://foreseeti.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ztlang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class TestUser extends ZTLangTest {
  private static class ZTLangModel {
    public final ControlPlane controlplane = new ControlPlane("control plane");

    public final User alice = new User("alice");
    public final User bob   = new User("bob");
    public final EnterpriseResource resource = new EnterpriseResource("resource");
    public final AccessPolicies accessPolicies = new AccessPolicies("access policies");
    public final Device alice_device = new Device("alice device", false);
    public final Device bob_device   = new Device("bob device"); //, true);
    public final UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    public final UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    public final Agent alice_agent = new Agent("alice agent");
    public final Agent bob_agent = new Agent("bob agent");

    public final AccessPolicies alice_accesspolicy = new AccessPolicies("Alice acesspolicy");
    public final AccessPolicies bob_accesspolicy = new AccessPolicies("Bob acesspolicy");

    public ZTLangModel() {
      controlplane.addAgent(alice_agent);
      controlplane.addAgent(bob_agent);

      controlplane.addResources(resource);
      controlplane.addResources(accessPolicies);

      alice.addDevices(alice_device);
      alice.addUserCredentials(alice_credentials);
      alice_agent.addDevice(alice_device);
      alice_agent.addUser(alice);
      alice_accesspolicy.addResource(resource);
      alice.addAccessPolicy(alice_accesspolicy);

      bob.addDevices(bob_device);
      bob.addUserCredentials(bob_credentials);
      bob_agent.addDevice(bob_device);
      bob_agent.addUser(bob);
      bob_accesspolicy.addResource(resource);
      bob.addAccessPolicy(bob_accesspolicy);

      //accessPolicies.addUsers(alice);
      //accessPolicies.addUsers(bob);
    }
  }

  @Test
  public void testAccessingAccessPoliciesLeadsToCompromisedCredentials() {
    // Attacker accesses the access policies which leads to phishing of Alice
    // successful phishing leads to compromise of alice's credentials
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.accessPolicies.Access);
    attacker.attack();

    model.alice_credentials.Compromise.assertCompromisedInstantaneously();
  }

  @Test
  public void testRequestAccessWithCorrectCredentialsAndDevice() {
    // Alice's credentials and device are compromised
    // thus a resource access request can be made by forming an agent
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.alice_device.Compromise);
    attacker.attack();

    model.alice_agent.FormAgent.assertCompromisedInstantaneously();
  }

  @Test
  public void testRequestAccessWithIncompatibleCredentialsAndDevice() {
    // Alice's credentials and device are compromised
    // thus a resource access request can be made by forming an agent
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.bob_device.Compromise);
    attacker.attack();

    model.alice_agent.FormAgent.assertUncompromised();
  }
}
