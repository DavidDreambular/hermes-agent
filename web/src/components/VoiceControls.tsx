import { Button } from "@nous-research/ui/ui/components/button";
import { Mic, Send, Square, Volume2, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { fetchJSON } from "@/lib/api";
import { cn } from "@/lib/utils";

interface TranscriptionResponse {
  ok: boolean;
  transcript: string;
  provider?: string;
}

interface SpeechResponse {
  ok: boolean;
  data_url: string;
  mime_type: string;
  provider?: string;
}

interface VoiceControlsProps {
  connected: boolean;
  profile?: string;
  onReadLastResponse: () => Promise<string>;
  onSendTranscript: (text: string) => boolean;
}

type VoiceState =
  | "idle"
  | "recording"
  | "transcribing"
  | "confirming"
  | "speaking";

const MAX_RECORDING_MS = 45_000;

function profileQuery(profile?: string): string {
  return profile ? `?profile=${encodeURIComponent(profile)}` : "";
}

function recordingMimeType(): string {
  return (
    [
      "audio/webm;codecs=opus",
      "audio/webm",
      "audio/ogg;codecs=opus",
      "audio/ogg",
      "audio/mp4",
    ].find((candidate) => MediaRecorder.isTypeSupported(candidate)) ?? ""
  );
}

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("No se pudo leer la grabación."));
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.readAsDataURL(blob);
  });
}

export function VoiceControls({
  connected,
  profile,
  onReadLastResponse,
  onSendTranscript,
}: VoiceControlsProps) {
  const [state, setState] = useState<VoiceState>("idle");
  const [transcript, setTranscript] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const timeoutRef = useRef<number | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);

  const releaseMicrophone = useCallback(() => {
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    recorderRef.current = null;
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  useEffect(
    () => () => {
      if (recorderRef.current?.state === "recording") {
        recorderRef.current.stop();
      }
      releaseMicrophone();
      audioRef.current?.pause();
    },
    [releaseMicrophone],
  );

  const transcribe = useCallback(
    async (blob: Blob) => {
      setState("transcribing");
      setError(null);
      try {
        const dataUrl = await blobToDataUrl(blob);
        const result = await fetchJSON<TranscriptionResponse>(
          `/api/audio/transcribe${profileQuery(profile)}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data_url: dataUrl, mime_type: blob.type }),
          },
        );
        const text = result.transcript.trim();
        if (!text) {
          throw new Error("No se detectó voz. Inténtalo de nuevo.");
        }
        setTranscript(text);
        setState("confirming");
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Falló la transcripción.");
        setState("idle");
      }
    },
    [profile],
  );

  const startRecording = useCallback(async () => {
    if (!connected) {
      setError("El chat todavía no está conectado.");
      return;
    }
    if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
      setError("El micrófono requiere HTTPS y un navegador compatible.");
      return;
    }
    setError(null);
    setAudioUrl(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true },
      });
      const mimeType = recordingMimeType();
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      chunksRef.current = [];
      streamRef.current = stream;
      recorderRef.current = recorder;
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) chunksRef.current.push(event.data);
      };
      recorder.onerror = () => {
        releaseMicrophone();
        setError("El navegador no pudo grabar el micrófono.");
        setState("idle");
      };
      recorder.onstop = () => {
        const chunks = chunksRef.current;
        chunksRef.current = [];
        const type = recorder.mimeType || mimeType || "audio/webm";
        releaseMicrophone();
        if (!chunks.length) {
          setError("La grabación está vacía.");
          setState("idle");
          return;
        }
        void transcribe(new Blob(chunks, { type }));
      };
      recorder.start(250);
      setState("recording");
      timeoutRef.current = window.setTimeout(() => {
        if (recorder.state === "recording") recorder.stop();
      }, MAX_RECORDING_MS);
    } catch (reason) {
      releaseMicrophone();
      const name = reason instanceof DOMException ? reason.name : "";
      setError(
        name === "NotAllowedError"
          ? "Permite el micrófono para este dominio privado."
          : "No se pudo abrir el micrófono.",
      );
      setState("idle");
    }
  }, [connected, releaseMicrophone, transcribe]);

  const stopRecording = useCallback(() => {
    const recorder = recorderRef.current;
    if (recorder?.state === "recording") recorder.stop();
  }, []);

  const cancelTranscript = useCallback(() => {
    setTranscript("");
    setError(null);
    setState("idle");
  }, []);

  const sendTranscript = useCallback(() => {
    const clean = transcript.replace(/[\r\n]+/g, " ").trim();
    if (!clean) return;
    if (!onSendTranscript(clean)) {
      setError("El chat perdió la conexión. Reinténtalo cuando reconecte.");
      return;
    }
    setTranscript("");
    setState("idle");
  }, [onSendTranscript, transcript]);

  const speak = useCallback(
    async (text: string) => {
      const clean = text.trim();
      if (!clean) throw new Error("No hay texto para reproducir.");
      setState("speaking");
      setError(null);
      try {
        const result = await fetchJSON<SpeechResponse>(
          `/api/audio/speak${profileQuery(profile)}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text: clean }),
          },
        );
        setAudioUrl(result.data_url);
        window.setTimeout(() => {
          void audioRef.current?.play().catch(() => {
            setError("Pulsa reproducir en el control de audio.");
          });
        }, 0);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Falló la síntesis de voz.");
      } finally {
        setState(transcript ? "confirming" : "idle");
      }
    },
    [profile, transcript],
  );

  const readLastResponse = useCallback(async () => {
    try {
      await speak(await onReadLastResponse());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "No se pudo leer la respuesta.");
      setState(transcript ? "confirming" : "idle");
    }
  }, [onReadLastResponse, speak, transcript]);

  return (
    <div className="absolute bottom-2 left-2 z-20 flex max-w-[calc(100%-7rem)] flex-col gap-2 sm:bottom-3 sm:left-3">
      {state === "confirming" && (
        <div className="w-[min(36rem,calc(100vw-3rem))] border border-current/40 bg-black/95 p-3 text-white shadow-xl">
          <div className="mb-2 text-xs font-semibold tracking-wide">
            Revisa la transcripción antes de enviarla
          </div>
          <textarea
            value={transcript}
            onChange={(event) => setTranscript(event.target.value)}
            rows={3}
            maxLength={4000}
            className="w-full resize-none border border-white/30 bg-black px-2 py-1.5 text-sm text-white outline-none focus:border-white/70"
            aria-label="Transcripción de voz"
          />
          <div className="mt-2 flex flex-wrap gap-2">
            <Button size="sm" onClick={sendTranscript} prefix={<Send className="h-4 w-4" />}>
              Enviar
            </Button>
            <Button
              size="sm"
              outlined
              onClick={() => void speak(transcript)}
              prefix={<Volume2 className="h-4 w-4" />}
            >
              Escuchar
            </Button>
            <Button size="sm" ghost onClick={cancelTranscript} prefix={<X className="h-4 w-4" />}>
              Cancelar
            </Button>
          </div>
        </div>
      )}

      {error && (
        <div className="max-w-sm border border-warning/60 bg-black/90 px-3 py-2 text-xs text-warning">
          {error}
        </div>
      )}

      {audioUrl && <audio ref={audioRef} controls src={audioUrl} className="h-9 max-w-full" />}

      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          outlined={state !== "recording"}
          disabled={state === "transcribing" || state === "speaking" || state === "confirming"}
          onClick={state === "recording" ? stopRecording : () => void startRecording()}
          prefix={state === "recording" ? <Square className="h-4 w-4" /> : <Mic className="h-4 w-4" />}
          aria-label={state === "recording" ? "Detener grabación" : "Hablar con Hermes"}
          className={cn("bg-black/75", state === "recording" && "border-danger text-danger")}
        >
          {state === "recording"
            ? "Detener"
            : state === "transcribing"
              ? "Transcribiendo…"
              : state === "speaking"
                ? "Preparando audio…"
                : "Hablar"}
        </Button>
        <Button
          size="sm"
          ghost
          disabled={!connected || state === "recording" || state === "transcribing" || state === "speaking"}
          onClick={() => void readLastResponse()}
          prefix={<Volume2 className="h-4 w-4" />}
          className="bg-black/75"
        >
          Leer respuesta
        </Button>
      </div>
    </div>
  );
}
