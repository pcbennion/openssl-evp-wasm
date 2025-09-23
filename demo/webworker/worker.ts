type PendingRequest = {
    resolve: (value: any) => void;
    reject: (reason?: any) => void;
};

export interface IWasmWorker {
    handleMessage(event: MessageEvent): void;
    handleError(event: ErrorEvent): void;
    sendRequest(event: string, payload: any, transfer: Transferable[]): Promise<any>;
}

export class WasmWorker implements IWasmWorker {
    private requestId = 0;
    private pending: Map<number, PendingRequest> = new Map();

    constructor(private worker: Worker) {
        this.worker.addEventListener('message', this.handleMessage);
        this.worker.addEventListener('error', this.handleError);
    }

    handleMessage = (event: MessageEvent) => {
        const {id, result, error} = event.data;
        const pending = this.pending.get(id);
        if (!pending) {
            return;
        }
        this.pending.delete(id);
        if (error) {
            pending.reject(error instanceof Error ? error : new Error(String(error)));
        } else {
            pending.resolve(result);
        }
    };

    handleError = (event: ErrorEvent) => {
        this.pending.forEach(({reject}) => reject(event));
        this.pending.clear();
    };

    sendRequest(event: string, payload?: any, transfer: Transferable[] = []): Promise<any> {
        const id = ++this.requestId;
        return new Promise((resolve, reject) => {
            this.pending.set(id, {resolve, reject});
            this.worker.postMessage({id, event, ...payload}, transfer);
        });
    }
}
