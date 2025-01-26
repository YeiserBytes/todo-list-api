import { describe, beforeAll, it, expect } from "bun:test";
import request from "supertest";
import app from "./index";

describe("API Test", () => {
  let token: string;

  beforeAll(async () => {
    const user = {
      email: "test@example.com",
      password: "password",
    }

    await request(app).post("/register").send({
      name: "Test",
      ...user
    });

    const res = await request(app).post("/login").send(user);
    token = res.body.accessToken;
  })

  it("should create a new todo", async () => {
    const res = await request(app)
      .post("/todo")
      .set("Authorization", `Bearer ${token}`)
      .send({ title: "Test Todo", description: "Description" })

    expect(res.status).toBe(201)
    expect(res.body.title).toBe("Test Todo")
  })

it("should fetch all todos", async () => {
const res = await request(app)
    .get("/todos")
    .set("Authorization", `Bearer ${token}`)

expect(res.status).toBe(200)
})
});
