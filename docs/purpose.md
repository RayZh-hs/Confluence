# Statement of Purpose

Tailscale and Headscale together have provided users with a production-grade open source solution for building virtual private networks for themselves or across a project. It boasts good algorithms for connecting machines via the shortest-delaying path.

However, when using these solutions, I find that creating a unifying network for all does not always cater to our everyday needs. Many a times, we wish for one node to coexist in different Tailnets, or to have user-level tailscale instances, or having a distributed variant where everyone can start and join Tailnets. The traditional approach of tying machine, user and network together does not cater well to those diverse needs.

Tailscale is born a company tool, where administration is centralized and the network follows a strict hierarchy. It is convenient but rather heavy, and it is far from flexible in usage.

Thus is born Confluence: A fast, flexible and distributed solution for building virtual networks and machine sharing. For concrete design of the architecture, refer to [Architecture](architecture.md), and for user usage, refer to [User Guide](user-guide.md). A full set of features is available in the [API Reference](api.md).

Specific use cases for Confluence include:

- Alice and her friends play Minecraft together, and they want to expose their local computers to each other. Traditional Fast Reverse Proxying forces all network traffic to go through a single node, but with Confluence, each person can select a best route to connect to the server's addrport with minimal latency and lag. In traditional Tailscale, although they can do this they must merge their Tailnets, and an administrator can control all the nodes.
- Bob is a developer who wants to share a local development project, served on dev machine, with fellow workers, without exposing it to the public. The project is for internal eyes only, and with Confluence, Bob can create a temporary Group and invite his colleagues to join, allowing them to access the dev machine's specific port without needing to merge Tailnets. Joining and leaving the group is easy, and Bob can revoke access at any time.
- A research institution wants to start a collaborative project with multiple universities, where each university may infrequently have nodes or endpoints to share with others. It may choose Confluence as the backend, enabling each university to share its own work with others, and each having equal control over their own nodes and none of others'.
