import type { z } from 'zod'
import type { FetchCallback } from './types'
import { addSearchParams } from './url'
import { validate } from './validate'

/**
 *
 * Compares the media type of a content-type header, ignoring parameters such as `charset` and case (RFC 9110 8.3.1).
 *
 */
export const hasMediaType = (contentType: string | null, mediaType: string) =>
  contentType?.split(';')[0]?.trim().toLowerCase() === mediaType.toLowerCase()

const get = async <T extends z.ZodSchema>({
  url,
  searchParams,
  responseValidationSchema,
  requiredContentType,
  fetchCallback = global.fetch,
}: {
  url: string
  searchParams?: Record<string, string>
  responseValidationSchema?: T
  requiredContentType?: string
  fetchCallback?: FetchCallback
}): Promise<typeof responseValidationSchema extends T ? z.output<T> : string> => {
  // Fetch the url with the search params
  const urlSearchParams = new URLSearchParams(searchParams)
  const urlWithSearchParams = urlSearchParams.size > 0 ? addSearchParams(url, urlSearchParams) : url
  const response = await fetchCallback(urlWithSearchParams, {
    method: 'GET',
  })

  if (!response.ok) {
    throw new Error(`request to '${urlWithSearchParams}' failed with status ${response.status}`)
  }

  // validate the expected content-type
  if (requiredContentType && !hasMediaType(response.headers.get('content-type'), requiredContentType)) {
    throw new Error(
      `received content-type '${response.headers.get(
        'content-type'
      )}' does not equal expected content-type '${requiredContentType}'`
    )
  }

  // If we pass in a validation schema, we expect JSON output
  if (responseValidationSchema) {
    const json = await response.json()
    return validate({
      data: json,
      schema: responseValidationSchema,
      errorMessage: 'invalid response from the GET call',
    })
  }

  // If no validation schema is passed in, we expect a string as response
  const text = await response.text()
  return text
}

/**
 *
 * @todo make get/post use the same method private internally as changes with apply to both
 *
 */
const post = async ({
  url,
  body,
  responseValidationSchema,
  fetchCallback = global.fetch,
}: {
  url: string
  body?: Record<string, unknown>
  responseValidationSchema?: z.ZodSchema
  fetchCallback?: FetchCallback
}) => {
  const response = await fetchCallback(url, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
    headers: { 'Content-Type': 'application/json' },
  })

  if (responseValidationSchema) {
    const json = await response.json()
    return validate({
      data: json,
      schema: responseValidationSchema,
      errorMessage: 'invalid response from a POST call',
    })
  }

  const text = await response.text()

  return text
}

export const fetcher = {
  get,
  post,
} as const
