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

public class TestAccessPolicies extends ZTLangTest {

  @Test
  public void testAccessResourceWithoutAccessPolicies() {
    // Bobs tries to access resource without accessRights, and fails

    // Adding assets
    ControlPlane controlplane = new ControlPlane("control plane");
    User bob   = new User("bob");
    EnterpriseResource resource = new EnterpriseResource("resource");
    Device bob_device   = new Device("bob device", false);
    UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    Agent bob_agent = new Agent("bob agent");
    AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");

    // Setting up associations
    controlplane.addAgent(bob_agent);
    controlplane.addResources(resource);
    bob.addDevices(bob_device);
    bob.addUserCredentials(bob_credentials);
    bob_agent.addDevice(bob_device);
    bob_agent.addUser(bob);
    bob.addAccessPolicy(bob_accesspolicy);

    // Attacker
    var attacker = new Attacker();

    // Attack steps
    attacker.addAttackPoint(bob_credentials.Compromise);
    attacker.addAttackPoint(bob_device.Compromise);

    attacker.attack();

    resource.Access.assertUncompromised();
  }

  @Test
  public void testAccessResourceWithAccessPolicies() {
    // Alices accesses resource with accessRights

    // Adding assets
    ControlPlane controlplane = new ControlPlane("control plane");
    User alice = new User("alice");
    EnterpriseResource resource = new EnterpriseResource("resource");
    Device alice_device = new Device("alice device", false);
    UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    Agent alice_agent = new Agent("alice agent");
    AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");

    // Setting up associations
    controlplane.addAgent(alice_agent);
    controlplane.addResources(resource);
    alice.addDevices(alice_device);
    alice.addUserCredentials(alice_credentials);
    alice_agent.addDevice(alice_device);
    alice_agent.addUser(alice);
    alice_accesspolicy.addResource(resource);
    alice.addAccessPolicy(alice_accesspolicy);

    // Attacker
    var attacker = new Attacker();

    // Attack steps
    attacker.addAttackPoint(alice_credentials.Compromise);
    attacker.addAttackPoint(alice_device.Compromise);
    attacker.attack();

    resource.Access.assertCompromisedInstantaneously();
  }

  @Test
  public void testAccessPoliciesToOneResourceDoesntGiveAccessToAll() {
    // Bob tries to access Resource B but has only accessRights to Resource A

    // Adding assets
    ControlPlane controlplane = new ControlPlane("control plane");
    User bob   = new User("bob");
    EnterpriseResource resource_A = new EnterpriseResource("resource A");
    EnterpriseResource resource_B = new EnterpriseResource("resource B");
    Device bob_device   = new Device("bob device", false);
    UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    Agent bob_agent = new Agent("bob agent");
    AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");

    // Setting up associations
    controlplane.addAgent(bob_agent);
    controlplane.addResources(resource_A);
    controlplane.addResources(resource_B);
    bob.addDevices(bob_device);
    bob.addUserCredentials(bob_credentials);
    bob_agent.addDevice(bob_device);
    bob_agent.addUser(bob);
    bob_accesspolicy.addResource(resource_A);
    bob.addAccessPolicy(bob_accesspolicy);

    // Attacker
    var attacker = new Attacker();

    // Attack steps
    attacker.addAttackPoint(bob_credentials.Compromise);
    attacker.addAttackPoint(bob_device.Compromise);

    attacker.attack();

    resource_B.Access.assertUncompromised();
  }

  @Test
  public void testAccessToOneResourceForOneUserDoesntGiveAccessForAllUsers() {
    // Bob tries to access Resource B but has only accessRights to Resource A

    // Adding assets
    ControlPlane controlplane = new ControlPlane("control plane");

    EnterpriseResource resource = new EnterpriseResource("resource");

    User alice = new User("alice");
    Device alice_device = new Device("alice device", false);
    UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    Agent alice_agent = new Agent("alice agent");
    AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");

    User bob = new User("bob");
    Device bob_device   = new Device("bob device", false);
    UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
    Agent bob_agent = new Agent("bob agent");
    AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");


    // Setting up associations
    controlplane.addAgent(bob_agent);
    controlplane.addAgent(alice_agent);
    controlplane.addResources(resource);

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
    bob.addAccessPolicy(bob_accesspolicy);

    // Attacker
    var attacker = new Attacker();

    // Attack steps
    attacker.addAttackPoint(bob_credentials.Compromise);
    attacker.addAttackPoint(bob_device.Compromise);

    attacker.attack();

    resource.Access.assertUncompromised();
  }

  // @Test
  // public void testCompromiseAccessPoliciesAndPhishing() {
  //   // Adding assets
  //   ControlPlane controlplane = new ControlPlane("control plane");

  //   EnterpriseResource resource = new EnterpriseResource("resource");
  //   EnterpriseResource accessPolicies = new EnterpriseResource("accessPolicies");

  //   User alice = new User("alice");
  //   Device alice_device = new Device("alice device", false);
  //   UserCredentials alice_credentials = new UserCredentials("alice_credentials");
  //   Agent alice_agent = new Agent("alice agent");
  //   AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");

  //   User bob = new User("bob");
  //   Device bob_device   = new Device("bob device", false);
  //   UserCredentials bob_credentials   = new UserCredentials("bob_credentials");
  //   Agent bob_agent = new Agent("bob agent");
  //   AccessPolicy bob_accesspolicy = new AccessPolicy("Bob acesspolicy");

  //   // Setting up associations
  //   controlplane.addAgent(bob_agent);
  //   controlplane.addAgent(alice_agent);
  //   controlplane.addResources(resource);
  //   controlplane.addResources(accessPolicies);

  //   alice.addDevices(alice_device);
  //   alice.addUserCredentials(alice_credentials);
  //   alice_agent.addDevice(alice_device);
  //   alice_agent.addUser(alice);
  //   alice_accesspolicy.addResource(resource);
  //   alice.addAccessPolicy(alice_accesspolicy);

  //   bob.addDevices(bob_device);
  //   bob.addUserCredentials(bob_credentials);
  //   bob_agent.addDevice(bob_device);
  //   bob_agent.addUser(bob);
  //   bob_accesspolicy.addResource(accessPolicies);
  //   bob.addAccessPolicy(bob_accesspolicy);

  //   accessPolicies.addAccessPolicy(alice_accesspolicy);
  //   accessPolicies.addAccessPolicy(bob_accesspolicy);

  //   var attacker = new Attacker();

  //   attacker.addAttackPoint(bob_credentials.Compromise);
  //   attacker.addAttackPoint(bob_device.Compromise);

  //   attacker.addAttackPoint(alice_device.Compromise);
  //   attacker.attack();

  //   resource.Access.assertCompromisedInstantaneously();
  // }


  @Test
  public void testCompromiseAccessPoliciesAndPhishing() {
    // Adding assets
    ControlPlane controlplane = new ControlPlane("control plane");

    User alice = new User("alice");
    User charlie   = new User("charlie");
    EnterpriseResource resource = new EnterpriseResource("resource");
    AccessPolicies accessPolicies = new AccessPolicies("access policies");
    Device alice_device = new Device("alice device", false);
    Device charlie_device = new Device("charlie device", false);
    UserCredentials alice_credentials = new UserCredentials("alice_credentials");
    UserCredentials charlie_credentials   = new UserCredentials("charlie_credentials");
    Agent alice_agent = new Agent("alice agent");
    Agent charlie_agent = new Agent("charlie agent");

    AccessPolicy alice_accesspolicy = new AccessPolicy("Alice acesspolicy");
    AccessPolicy charlie_accesspolicy = new AccessPolicy("Charlie acesspolicy");

    controlplane.addAgent(alice_agent);
    controlplane.addAgent(charlie_agent);
    controlplane.addResources(resource);
    controlplane.addResources(accessPolicies);

    alice.addDevices(alice_device);
    alice.addUserCredentials(alice_credentials);
    alice_agent.addDevice(alice_device);
    alice_agent.addUser(alice);

    charlie.addDevices(charlie_device);
    charlie.addUserCredentials(charlie_credentials);
    charlie_agent.addDevice(charlie_device);
    charlie_agent.addUser(charlie);

    alice.addAccessPolicy(alice_accesspolicy);
    charlie.addAccessPolicy(charlie_accesspolicy);

    alice_accesspolicy.addUser(alice);

    alice_accesspolicy.addResource(resource);
    charlie_accesspolicy.addResource(accessPolicies);

    accessPolicies.addAccessPolicy(alice_accesspolicy);
    accessPolicies.addAccessPolicy(charlie_accesspolicy);

    controlplane.addStoredPolicy(alice_accesspolicy);

    var attacker = new Attacker();

    attacker.addAttackPoint(charlie_credentials.Compromise);
    attacker.addAttackPoint(charlie_device.Compromise);

    attacker.addAttackPoint(alice_device.Compromise);
    attacker.attack();

    resource.Access.assertCompromisedInstantaneously();
  }

}



