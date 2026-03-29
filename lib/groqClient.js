import Groq from "groq-sdk";

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

export async function generateResponse(messages) {
  try {
    const completion = await groq.chat.completions.create({
      model: "llama3-8b-8192", // or mixtral, llama3-70b, etc.
      messages,
      temperature: 0.7,
    });

    return completion.choices[0]?.message?.content || "";
  } catch (error) {
    console.error("Groq error:", error);
    throw error;
  }
}