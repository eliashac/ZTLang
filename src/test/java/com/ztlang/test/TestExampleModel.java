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

public class TestExampleModel extends ZTLangTest {
  private static class ZTLangModel {
    public final ControlPlane controlplane = new ControlPlane("control plane");

    public final User alice = new User("alice");
    public final User bob   = new User("bob");
    public final User charlie   = new User("charlie");
    
    public final EnterpriseResource organization_database = new EnterpriseResource("Organization Database");
    public final EnterpriseResource organization_web_service = new EnterpriseResource("Organization Web Service");
    public final AccessPolicies accessPolicies = new AccessPolicies("access policies");
    
    public final Device alice_laptop = new Device("Alice Laptop", false);
    public final Device bob_laptop   = new Device("Bob Laptop", false);
    public final Device charlie_laptop = new Device("Charlie Laptop", true);
    public final Device alice_phone = new Device("Alice Phone", false);
    
    public final UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    public final UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    public final UserCredentials charlie_credentials   = new UserCredentials("charlie_credentials");
    
    public final Agent alice_agent_a = new Agent("alice agent a");
    public final Agent alice_agent_b = new Agent("alice agent b");
    public final Agent bob_agent = new Agent("bob agent");
    public final Agent charlie_agent = new Agent("charlie agent");

    public final AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");
    public final AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");
    public final AccessPolicy charlie_accesspolicy = new AccessPolicy("Charlie acesspolicy");

    public ZTLangModel() {
      controlplane.addAgent(alice_agent_a);
      controlplane.addAgent(alice_agent_b);
      controlplane.addAgent(bob_agent);
      controlplane.addAgent(charlie_agent);
      controlplane.addResources(organization_database);
      controlplane.addResources(organization_web_service);
      controlplane.addResources(accessPolicies);

      alice.addDevices(alice_laptop);
      alice.addDevices(alice_phone);
      alice.addUserCredentials(alice_credentials);
      alice_agent_a.addDevice(alice_laptop);
      alice_agent_b.addDevice(alice_phone);
      alice_agent_a.addUser(alice);
      alice_agent_b.addUser(alice);

      bob.addDevices(bob_laptop);
      bob.addUserCredentials(bob_credentials);
      bob_agent.addDevice(bob_laptop);
      bob_agent.addUser(bob);

      charlie.addDevices(charlie_laptop);
      charlie.addUserCredentials(charlie_credentials);
      charlie_agent.addDevice(charlie_laptop);
      charlie_agent.addUser(charlie);

      alice.addAccessPolicy(alice_accesspolicy);
      bob.addAccessPolicy(bob_accesspolicy);
      charlie.addAccessPolicy(charlie_accesspolicy);

      alice_accesspolicy.addResource(organization_database);
      alice_accesspolicy.addResource(organization_web_service);
      alice_accesspolicy.addResource(accessPolicies);
      bob_accesspolicy.addResource(organization_web_service);

      accessPolicies.addAccessPolicy(alice_accesspolicy);
      accessPolicies.addAccessPolicy(bob_accesspolicy);
      accessPolicies.addAccessPolicy(charlie_accesspolicy);

      controlplane.addStoredPolicy(alice_accesspolicy);
      controlplane.addStoredPolicy(bob_accesspolicy);
      controlplane.addStoredPolicy(charlie_accesspolicy);
    }
  }

  @Test
  public void testCompromiseCredentialsButNotDevice1() {
    var model = new ZTLangModel();
    var attacker = new Attacker();

    attacker.addAttackPoint(model.alice_credentials.Compromise);
    attacker.addAttackPoint(model.alice_laptop.Compromise);
    attacker.attack();

    model.organization_database.Access.assertCompromisedInstantaneously();
  }


}
