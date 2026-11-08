// Vercel serverless endpoint: public-landmark-only image research.
export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Método não permitido." });
  if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: "O GEOINT automático ainda não foi configurado. Adicione OPENAI_API_KEY nas variáveis de ambiente da Vercel." });

  try {
    const { image, clues = "" } = req.body || {};
    if (typeof image !== "string" || !/^data:image\/(jpeg|png|webp);base64,/.test(image) || image.length > 4_200_000) {
      return res.status(400).json({ error: "Envie uma imagem JPG, PNG ou WebP de até 3 MB." });
    }
    const response = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        store: false,
        input: [{
          role: "user",
          content: [
            { type: "input_text", text: `Analise a imagem SOMENTE para reconhecer um ponto de referência público, amplamente conhecido e destinado à visitação (por exemplo, monumento, museu, parque ou praça pública). Nunca tente localizar uma residência, rua residencial, comércio pequeno, escola privada, pessoa, rotina ou endereço. Não use placas de veículos, rostos, números de casas ou metadados para inferir localização. Se não houver um marco público reconhecível com boa evidência visual, retorne found=false. Pistas opcionais: ${String(clues).slice(0,300)}. Responda SOMENTE JSON válido: {"found":boolean,"landmark":string,"city":string,"region":string,"country":string,"confidence":"alta"|"média"|"baixa","reason":string}. Não inclua rua, número, coordenadas nem endereço. Seja conservador e não invente nomes.` },
            { type: "input_image", image_url: image, detail: "high" }
          ]
        }]
      })
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error("TRACE GEOINT OpenAI error:", response.status, payload?.error?.code || payload?.error?.type || "unknown");
      if (response.status === 401) {
        return res.status(502).json({ error: "A chave da OpenAI é inválida, foi revogada ou não está configurada corretamente na Vercel. Confira OPENAI_API_KEY e faça um novo deploy." });
      }
      if (response.status === 429) {
        return res.status(502).json({ error: "A API da OpenAI está sem cota disponível ou atingiu um limite. Confira o faturamento e os limites da API." });
      }
      if (response.status === 400) {
        return res.status(502).json({ error: "A OpenAI recusou o formato da solicitação ou da imagem. Tente uma imagem JPG ou PNG menor." });
      }
      return res.status(502).json({ error: "A OpenAI retornou um erro (HTTP " + response.status + "). Confira os logs da função GEOINT na Vercel." });
    }
    const text = payload.output?.flatMap(item => item.content || []).find(item => item.type === "output_text")?.text || "";
    const parsed = JSON.parse(text.replace(/^```json\s*|\s*```$/g, "").trim());
    if (!parsed.found || !parsed.landmark || !parsed.city || parsed.confidence === "baixa") {
      return res.status(200).json({ found: false, message: "Não encontrei um ponto de referência público com confiança suficiente. A imagem pode mostrar uma rua comum ou um local privado; não vou tentar localizar esse tipo de lugar." });
    }

    const query = [parsed.landmark, parsed.city, parsed.region, parsed.country].filter(Boolean).join(", ");
    const geo = await fetch("https://nominatim.openstreetmap.org/search?format=jsonv2&limit=5&q=" + encodeURIComponent(query), {
      headers: { "User-Agent": "TRACE-OSINT-Dashboard/1.0 (public landmark research)" }
    });
    if (!geo.ok) return res.status(200).json({ found: true, ...parsed, map: null, message: "Marco público sugerido, mas o serviço de mapas não respondeu." });
    const candidates = await geo.json();
    const place = candidates.find(item => ["tourism", "historic", "leisure"].includes(item.class));
    if (!place) return res.status(200).json({ found: true, ...parsed, map: null, message: "Possível marco público identificado, mas não encontrei uma correspondência cartográfica suficientemente clara." });

    return res.status(200).json({
      found: true,
      landmark: parsed.landmark,
      city: parsed.city,
      region: parsed.region,
      country: parsed.country,
      confidence: parsed.confidence,
      reason: parsed.reason,
      map: { lat: Number(place.lat), lon: Number(place.lon), label: place.display_name, osm: "https://www.openstreetmap.org/?mlat=" + encodeURIComponent(place.lat) + "&mlon=" + encodeURIComponent(place.lon) + "#map=16/" + encodeURIComponent(place.lat) + "/" + encodeURIComponent(place.lon) }
    });
  } catch {
    return res.status(500).json({ error: "Não foi possível analisar a imagem. Verifique o arquivo e tente novamente." });
  }
}
